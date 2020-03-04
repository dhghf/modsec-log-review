export interface Reviewer {
  getReview(): string | Promise<string>
}
