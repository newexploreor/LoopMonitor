import { describe, expect, it } from "vitest";
import { formatAvailability, formatDuration, formatLatency } from "./format";

describe("formatters", () => {
  it("shows a dash when availability has no samples", () => {
    expect(formatAvailability(null)).toBe("--");
    expect(formatAvailability(undefined)).toBe("--");
  });

  it("formats availability and latency", () => {
    expect(formatAvailability(99.5)).toBe("99.50%");
    expect(formatLatency(12.4)).toBe("12 ms");
    expect(formatLatency(null)).toBe("--");
  });

  it("formats incident duration", () => {
    expect(formatDuration(45)).toBe("45 秒");
    expect(formatDuration(125)).toBe("2 分 5 秒");
  });
});
