// Small shared value helpers used across formatting modules.

export function hasValue(value) {
  return value !== null && value !== undefined && value !== ''
}

export function displayValue(value, fallback = '—') {
  return hasValue(value) ? String(value) : fallback
}
