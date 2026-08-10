export function mimeMatches(contentType: string, bytes: Uint8Array): boolean {
  const prefix = (...values: number[]) =>
    values.every((value, index) => bytes[index] === value);
  if (contentType === "image/png")
    return prefix(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  if (contentType === "image/jpeg") return prefix(0xff, 0xd8, 0xff);
  if (contentType === "image/gif")
    return (
      new TextDecoder().decode(bytes.slice(0, 6)).match(/^GIF8[79]a$/) !== null
    );
  if (contentType === "image/webp")
    return (
      new TextDecoder().decode(bytes.slice(0, 4)) === "RIFF" &&
      new TextDecoder().decode(bytes.slice(8, 12)) === "WEBP"
    );
  if (contentType === "audio/ogg" || contentType === "video/ogg")
    return new TextDecoder().decode(bytes.slice(0, 4)) === "OggS";
  if (contentType === "audio/mpeg")
    return (
      prefix(0x49, 0x44, 0x33) ||
      (bytes[0] === 0xff && (bytes[1]! & 0xe0) === 0xe0)
    );
  if (contentType === "application/pdf")
    return new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";
  return (
    contentType === "text/plain" || contentType === "application/octet-stream"
  );
}

export function validInstanceSetting(key: string, value: string): boolean {
  if (key === "registration.enabled") return ["true", "false"].includes(value);
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return false;
  if (key === "upload.file.bytes")
    return Number.isInteger(number) && number <= 500 * 1024 * 1024;
  if (key === "upload.daily_user.bytes" || key === "upload.guild.bytes")
    return Number.isInteger(number) && number <= 1024 ** 5;
  if (key === "voice.warning_gb_per_hour") return number <= 100;
  if (key === "export.retention_days")
    return Number.isInteger(number) && number <= 90;
  return false;
}
