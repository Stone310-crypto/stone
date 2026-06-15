interface AvatarProps {
  name: string;
  size?: number;
  online?: boolean;
}

const COLORS = [
  "#5b8aee", "#3ba55c", "#faa61a", "#ed4245",
  "#a855f7", "#ec4899", "#14b8a6", "#f97316",
];

function colorFor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return COLORS[h % COLORS.length];
}

export default function Avatar({ name, size = 36, online }: AvatarProps) {
  const initials = name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("") || "?";

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <div
        className="flex items-center justify-center rounded-full font-semibold select-none"
        style={{
          width: size,
          height: size,
          background: colorFor(name),
          color: "#fff",
          fontSize: Math.max(10, size * 0.36),
        }}
      >
        {initials}
      </div>
      {online != null && (
        <span
          className="absolute rounded-full border-2"
          style={{
            width: size * 0.32,
            height: size * 0.32,
            background: online ? "var(--green)" : "var(--text-muted)",
            borderColor: "var(--panel-bg)",
            bottom: 0,
            right: 0,
          }}
        />
      )}
    </div>
  );
}
