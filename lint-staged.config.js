export default {
	"**/*.{ts?(x),js?(x)}": "npm run lint:files",
	"**/*.{ts?(x),js?(x),md,html,json}": filenames =>
		`npm prettier:lint ${filenames.map(escapeFileName).join(" ")}`,
	"package.json": () => "npm install --frozen-lockfile"
};

function escapeFileName(str) {
	return `"${str}"`;
}
