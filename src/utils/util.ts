export function ms(duration: string) {
  let value = parseInt(duration);
  if (duration.endsWith("d")) {
    value = value * 24 * 60 * 60 * 1000;
  }
  if (duration.endsWith("h")) {
    value = value * 60 * 60 * 1000;
  }

  if (duration.endsWith("m")) {
    return value * 60 * 1000;
  }
  if (duration.endsWith("s")) {
    value = value * 1000;
  }

  return value;
}
