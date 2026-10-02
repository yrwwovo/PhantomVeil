#!/usr/bin/env node

import { fileURLToPath } from "node:url";

import { runPveil } from "../src/cli/pveil.ts";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
process.exitCode = await runPveil(projectRoot, process.argv.slice(2));
