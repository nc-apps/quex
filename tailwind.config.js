import formsPlugin from "@tailwindcss/forms";

/** @type {import('tailwindcss').Config} */
export default {
  content: ["templates/**/*.html"],
  theme: {
    extend: {},
  },
  plugins: [formsPlugin],
};
