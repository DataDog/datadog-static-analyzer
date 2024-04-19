import { op_tree_node_count } from "ext:core/ops";

function treeNodeCount() {
    return op_tree_node_count();
}

globalThis.fromRust = { treeNodeCount };
