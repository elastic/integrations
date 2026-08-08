/** One `| EVAL` step from Pass 4 domain documentation. */
export interface EvaluationSnippet {
  readonly id: string;
  readonly section: string;
  readonly esql: string;
}

export interface IntegrationEvaluations {
  readonly integration: string;
  readonly evaluations: readonly EvaluationSnippet[];
}
