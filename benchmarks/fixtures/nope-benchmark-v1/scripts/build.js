const { execSync } = require("child_process");

execSync("npm run build:" + process.env.BUILD_TARGET);
