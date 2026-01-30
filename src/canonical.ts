/**
 * Canonical JSON serialization per RFC 8785 (JCS).
 *
 * Rules:
 * - Object keys sorted lexicographically by Unicode code point
 * - No whitespace between tokens
 * - Numbers: no leading zeros, no trailing zeros in fractions,
 *   no positive sign, no scientific notation for integers
 * - Strings: minimal escaping (control chars, backslash, double-quote)
 * - null, true, false as literals
 */

export function canonicalJson(value: unknown): string {
  return serializeValue(value);
}

function serializeValue(value: unknown): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      return serializeNumber(value);

    case "string":
      return serializeString(value);

    case "object":
      if (Array.isArray(value)) {
        return serializeArray(value);
      }
      return serializeObject(value as Record<string, unknown>);

    default:
      // undefined, function, symbol -- omit per JSON spec
      return "null";
  }
}

function serializeNumber(num: number): string {
  if (!isFinite(num)) {
    return "null";
  }

  // RFC 8785: use the shortest representation that round-trips.
  // For integers, no decimal point or exponent.
  // For floats, use toString which gives shortest round-trip in V8.
  if (Number.isInteger(num) && Math.abs(num) < Number.MAX_SAFE_INTEGER) {
    // Avoid scientific notation for large integers
    if (Math.abs(num) < 1e20) {
      return num.toString();
    }
  }

  // ES2015+ Number.prototype.toString produces the shortest
  // round-tripping representation. RFC 8785 defers to ES
  // serialization rules (ECMAScript NumberToString).
  return JSON.stringify(num);
}

function serializeString(text: string): string {
  // Use JSON.stringify for proper escaping, which handles
  // control characters, backslash, and double-quote.
  return JSON.stringify(text);
}

function serializeArray(arr: unknown[]): string {
  const items = arr.map((item) => serializeValue(item));
  return "[" + items.join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const pairs: string[] = [];

  for (const key of keys) {
    const val = obj[key];
    // Skip undefined values (like JSON.stringify does)
    if (val === undefined) {
      continue;
    }
    pairs.push(serializeString(key) + ":" + serializeValue(val));
  }

  return "{" + pairs.join(",") + "}";
}
