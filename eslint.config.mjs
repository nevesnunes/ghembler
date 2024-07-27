import globals from "globals";
import pluginJs from "@eslint/js";

export default [
    {
        files: ["**/*.js"],
        languageOptions: { sourceType: "commonjs" },
    },
    {
        languageOptions: {
            globals: {
                monaco: "readonly",
                ...globals.browser,
            },
        },
        /*
        rules: {
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    caughtErrors: "all",
                    varsIgnorePattern: "^_",
                    argsIgnorePattern: "^_",
                },
            ],
        },
         */
    },
    pluginJs.configs.recommended,
];
