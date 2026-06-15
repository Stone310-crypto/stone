import { useQuery } from "@tanstack/react-query";
import { node } from "../api/stone";

export interface NodeHealth {
  connected: boolean;
  blockHeight: number;
  network: string;
  nodeId: string;
}

export function useNodeHealth(): NodeHealth {
  const q = useQuery({
    queryKey: ["node-health"],
    queryFn: node.health,
    refetchInterval: 10_000,
    retry: false,
    staleTime: 8_000,
  });

  if (q.data) {
    return {
      connected: true,
      blockHeight: q.data.block_height,
      network: q.data.network ?? "testnet",
      nodeId: q.data.node_id ?? "",
    };
  }
  return { connected: false, blockHeight: 0, network: "", nodeId: "" };
}
