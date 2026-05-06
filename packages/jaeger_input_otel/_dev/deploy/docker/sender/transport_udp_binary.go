// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/thrift"
	"github.com/uber/jaeger-client-go/thrift-gen/agent"
	jgen "github.com/uber/jaeger-client-go/thrift-gen/jaeger"
	"github.com/uber/jaeger-client-go/utils"
)

// emitBatchOverheadBinary reserves bytes for Thrift RPC framing; binary batches are larger than compact.
const emitBatchOverheadBinary = 200

var errSpanTooLargeBinary = errors.New("span is too large for UDP packet")

// binaryUDPAgent sends Jaeger Agent EmitBatch over UDP using Thrift binary protocol (port 6832).
type binaryUDPAgent struct {
	conn          *net.UDPConn
	thriftBuffer  *thrift.TMemoryBuffer
	client        *agent.AgentClient
	maxPacketSize int
}

func newBinaryUDPAgent(hostPort string, maxPacketSize int) (*binaryUDPAgent, error) {
	thriftBuffer := thrift.NewTMemoryBufferLen(maxPacketSize)
	protocolFactory := thrift.NewTBinaryProtocolFactory(true, true)
	client := agent.NewAgentClientFactory(thriftBuffer, protocolFactory)

	destAddr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetWriteBuffer(maxPacketSize); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &binaryUDPAgent{
		conn:          conn,
		thriftBuffer:  thriftBuffer,
		client:        client,
		maxPacketSize: maxPacketSize,
	}, nil
}

func (a *binaryUDPAgent) EmitBatch(ctx context.Context, batch *jgen.Batch) error {
	a.thriftBuffer.Reset()
	if err := a.client.EmitBatch(ctx, batch); err != nil {
		return err
	}
	if a.thriftBuffer.Len() > a.maxPacketSize {
		return fmt.Errorf("EmitBatch payload %d exceeds max UDP packet %d", a.thriftBuffer.Len(), a.maxPacketSize)
	}
	_, err := a.conn.Write(a.thriftBuffer.Bytes())
	return err
}

func (a *binaryUDPAgent) Close() error {
	return a.conn.Close()
}

// binaryUdpTransport implements jaeger.Transport for Thrift binary over UDP (matches upstream udpSender layout).
type binaryUdpTransport struct {
	client          *binaryUDPAgent
	maxPacketSize   int
	maxSpanBytes    int
	byteBufferSize  int
	spanBuffer      []*jgen.Span
	thriftBuffer    *thrift.TMemoryBuffer
	thriftProtocol  thrift.TProtocol
	process         *jgen.Process
	processByteSize int
	batchSeqNo      int64
}

func newBinaryUDPTransport(hostPort string, maxPacketSize int) (jaeger.Transport, error) {
	if maxPacketSize == 0 {
		maxPacketSize = utils.UDPPacketMaxLength
	}
	client, err := newBinaryUDPAgent(hostPort, maxPacketSize)
	if err != nil {
		return nil, err
	}

	protocolFactory := thrift.NewTBinaryProtocolFactory(true, true)
	thriftBuffer := thrift.NewTMemoryBufferLen(maxPacketSize)
	thriftProtocol := protocolFactory.GetProtocol(thriftBuffer)

	return &binaryUdpTransport{
		client:         client,
		maxPacketSize:  maxPacketSize,
		maxSpanBytes:   maxPacketSize - emitBatchOverheadBinary,
		thriftBuffer:   thriftBuffer,
		thriftProtocol: thriftProtocol,
	}, nil
}

func (s *binaryUdpTransport) calcSizeOfSerializedThrift(ts thrift.TStruct) int {
	s.thriftBuffer.Reset()
	_ = ts.Write(context.Background(), s.thriftProtocol)
	return s.thriftBuffer.Len()
}

func (s *binaryUdpTransport) Append(span *jaeger.Span) (int, error) {
	if s.process == nil {
		s.process = jaeger.BuildJaegerProcessThrift(span)
		s.processByteSize = s.calcSizeOfSerializedThrift(s.process)
		s.byteBufferSize += s.processByteSize
	}
	jSpan := jaeger.BuildJaegerThrift(span)
	spanSize := s.calcSizeOfSerializedThrift(jSpan)
	if spanSize > s.maxSpanBytes {
		return 1, errSpanTooLargeBinary
	}

	s.byteBufferSize += spanSize
	if s.byteBufferSize <= s.maxSpanBytes {
		s.spanBuffer = append(s.spanBuffer, jSpan)
		if s.byteBufferSize < s.maxSpanBytes {
			return 0, nil
		}
		return s.Flush()
	}
	n, err := s.Flush()
	s.spanBuffer = append(s.spanBuffer, jSpan)
	s.byteBufferSize = spanSize + s.processByteSize
	return n, err
}

func (s *binaryUdpTransport) Flush() (int, error) {
	n := len(s.spanBuffer)
	if n == 0 {
		return 0, nil
	}
	s.batchSeqNo++
	seqNo := s.batchSeqNo
	err := s.client.EmitBatch(context.Background(), &jgen.Batch{
		Process: s.process,
		Spans:   s.spanBuffer,
		SeqNo:   &seqNo,
		Stats: &jgen.ClientStats{
			TooLargeDroppedSpans: 0,
			FailedToEmitSpans:    0,
		},
	})
	s.resetBuffers()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *binaryUdpTransport) Close() error {
	return s.client.Close()
}

func (s *binaryUdpTransport) resetBuffers() {
	for i := range s.spanBuffer {
		s.spanBuffer[i] = nil
	}
	s.spanBuffer = s.spanBuffer[:0]
	s.byteBufferSize = s.processByteSize
}
