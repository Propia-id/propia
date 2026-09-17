import { deploy } from "./deploy-impl";

/// Full deployment: wallet implementation, beacon, dispatcher and all four
/// registries. For a single registry, see the `deploy` task.
deploy().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
