export default {
	"**/*.{ts?(x),js?(x)}": "npm run lint:files",
	"**/*.{ts?(x),js?(x),md,html,json}": filenames =>
		`npm run prettier:lint ${filenames.map(escapeFileName).join(" ")}`,
	"package.json": () => "npm install"
};

function escapeFileName(str) {
	return `"${str}"`;
}
