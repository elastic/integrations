FROM mcr.microsoft.com/windows:ltsc2019
RUN $ProgressPreference = 'SilentlyContinue'
RUN  Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.10.1-windows-x86_64.zip -OutFile elastic-agent-8.10.1-windows-x86_64.zip
RUN  Expand-Archive .\elastic-agent-8.10.1-windows-x86_64.zip -DestinationPath .
RUN  cd elastic-agent-8.10.1-windows-x86_64
ENTRYPOINT  [".\elastic-agent.exe", "container", @PSBoundParameters]