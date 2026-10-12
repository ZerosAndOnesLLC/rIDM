// The theme switch moved out of the console in 15.2 so every surface can use
// it; this re-export keeps the console's imports working until 15.12.
export { ThemeProvider, useTheme, type Theme } from "@/lib/theme/provider";
