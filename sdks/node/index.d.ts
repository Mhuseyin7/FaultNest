export interface CaptureOptions { file?: string }
export declare function captureError(error: Error, context?: Record<string, unknown>, options?: CaptureOptions): string;
