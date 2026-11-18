import { liveGate } from "../server/access";
import { endpoints } from "./endpoints";
import { createService } from "./service";
import { liveDeps } from "./wiring";

/** The live `/v1` handlers: the same service the MCP tools use, behind the key and rate-limit gate. */
export const v1 = endpoints(createService(liveDeps), liveGate);
