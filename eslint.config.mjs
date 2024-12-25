import eslintConfigPrettier from "eslint-config-prettier";
import globals from "globals";
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
	eslintConfigPrettier,
	...tseslint.config(eslint.configs.recommended, tseslint.configs.recommended),
	{
		languageOptions: {
			globals: {
				...globals.node
			},

			parserOptions: {
				project: true,
				projectService: {
					allowDefaultProject: [".prettierrc.cjs", ".scripts/*.ts"]
				},
				tsconfigRootDir: import.meta.dirname,
				projectFolderIgnoreList: ["**/node_modules/**"]
			}
		},
		rules: {
			"no-console": "off",
			"@typescript-eslint/no-explicit-any": "warn"
		}
	}
];
