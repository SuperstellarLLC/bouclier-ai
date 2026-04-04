const config = {
  "*.{js,jsx,ts,tsx,mjs,mts}": ["eslint --fix", "prettier --write"],
  "*.{json,css,md,yml,yaml}": ["prettier --write"],
};

export default config;
