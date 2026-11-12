export type MaskFunction = (value: unknown, path?: Array<string | number>) => unknown;

export interface ScrubOptions {
  /** Replacement text, or a function returning it. Default: "[REDACTED]" */
  mask?: string | MaskFunction;
  /** Extra sensitive key names (string) or patterns (RegExp). */
  keys?: Array<string | RegExp>;
  /** If true, `keys` replaces the built-in key list instead of extending it. */
  replaceDefaultKeys?: boolean;
  /** true = default patterns, false = none, or a list of names / RegExps. */
  patterns?: boolean | Array<string | RegExp>;
  /** Maximum nesting depth before "[MaxDepth]" is returned. Default: 20 */
  maxDepth?: number;
}

export function scrub<T = any>(value: T, options?: ScrubOptions): any;
export function scrubString(value: string, options?: ScrubOptions): string;
export function createScrubber(options?: ScrubOptions): <T = any>(value: T) => any;
export function expressMiddleware(
  options?: ScrubOptions
): (req: any, res: any, next: (err?: any) => void) => void;

export const DEFAULT_KEYS: string[];
export const PATTERN_NAMES: string[];
export const DEFAULT_PATTERN_NAMES: string[];
