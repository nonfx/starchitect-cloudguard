export default {
	"**/*.{ts?(x),js?(x)}": "bun run lint:files",
	"**/*.{ts?(x),js?(x),md,html,json}": filenames =>
		`bun prettier:lint ${filenames.map(escapeFileName).join(" ")}`,
	"package.json": () => "bun install --frozen-lockfile"
};

function escapeFileName(str) {
	return `"${str}"`;
}
