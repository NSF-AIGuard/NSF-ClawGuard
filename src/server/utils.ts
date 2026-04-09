/**
 * 解析 CSV 字符串为结构化数据
 * @param csvContent CSV 文件内容
 * @returns SecurityEvent[] 结构化的事件数组
 */
export function parseCSV<T>(csvContent: string, keys: Array<keyof T>): T[] {
  // 按行分割
  const lines = csvContent.split("\n");

  // 移除空行
  const nonEmptyLines = lines.filter((line) => line.trim());

  // 如果没有数据或只有表头，返回空数组
  if (nonEmptyLines.length <= 1) {
    return [];
  }
  const events: T[] = [];

  for (let i = 1; i < nonEmptyLines.length; i++) {
    const line = nonEmptyLines[i].trim();
    if (!line) continue;

    // 解析每行的数据，处理可能包含逗号的字段（如 recommendation 和 event_info）
    const values = parseCSVLine(line);

    const entries = keys.map((k, i) => [k, values[i] || ""]);
    const row = Object.fromEntries(entries) as T;
    events.push(row);
  }

  return events;
}
/**
 * 解析 CSV 行，处理包含逗号的字段（双引号包裹）
 * @param line CSV 行
 * @returns string[] 字段值数组
 */
function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      // 处理转义的双引号（两个双引号表示一个）
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++; // 跳过下一个双引号
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      // 逗号且不在引号内，表示字段分隔
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }

  // 添加最后一个字段
  result.push(current);

  return result;
}
