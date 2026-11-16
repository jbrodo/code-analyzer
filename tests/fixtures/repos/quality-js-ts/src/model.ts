export function parse(input: any): string {
  const ignored = 1;
  try {
    return String(input);
  } catch (error) {}
  return "";
}
