use crate::custom_serializer::base64;
use crate::{config::*, types::*, utils::helper_utils::hash_n_subhashes};
use plonky2::plonk::config::GenericHashOut;
use serde::{Deserialize, Serialize};

// This module implements a Merkle tree structure for storing and verifying data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    #[serde(
        serialize_with = "base64::serialize_option",
        deserialize_with = "base64::deserialize_option"
    )]
    hash: Option<Vec<u8>>,
    children: Option<Vec<Node>>,
}

impl Node {
    // Creates a new node with the given hash.
    pub fn new(hash: Option<Vec<u8>>) -> Self {
        Node {
            hash,
            children: None,
        }
    }

    // Returns the hash of the node.
    pub fn hash(&self) -> &Option<Vec<u8>> {
        &self.hash
    }

    pub fn set_hash(&mut self, hash: Vec<u8>) {
        self.hash = Some(hash);
    }

    pub fn set_children(&mut self, children: Vec<Node>) {
        self.children = Some(children);
    }

    fn collect_nodes_at_depth_mut<'a>(
        &'a mut self,
        target_depth: usize,
        result: &mut Vec<&'a mut Node>,
        current_depth: usize,
    ) {
        if current_depth == target_depth {
            result.push(self);
        } else if current_depth < target_depth
            && let Some(ref mut children) = self.children
        {
            for child in children {
                child.collect_nodes_at_depth_mut(target_depth, result, current_depth + 1);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: Node,
    pub depth: usize,
}

// This struct represents an adapted Merkle tree, which is not a binary tree where each non-leaf node is the hash of its children.
// Depth is the number of levels in the tree, starting from 1 for the root.
// Depth 1 --> root
// Depth 2 --> level 2
// Depth 3 --> level 3
// Depth n-1 --> level n-1
// Depth n --> leaves (merkle.depth)

impl MerkleTree {
    // Creates a new Merkle tree recursively with the given root hash and proof.
    pub fn new_from_leafs(leafs: Vec<Node>, depth: usize, batch: bool) -> Self {
        // recursively generate the entire tree structure from the leafs
        let mut nodes = Vec::new();

        // chunk the leafs into RECURSIVE_SIZE length chunks
        // if batch is true, chunk the leafs into BATCH_SIZE length chunks --> only in the first depth
        let mut padded_nodes = Vec::new();
        let chunks = if batch {
            // account leafs are already padded with BATCH_SIZE, but we need to pad the batch_circuit nodes
            leafs.chunks(BATCH_SIZE)
        } else {
            // must pad to be multiple of RECURSIVE_SIZE (if it is not the root)
            leafs.chunks(RECURSIVE_SIZE)
        };

        // pad to be multiple of RECURSIVE_SIZE
        if chunks.len() % RECURSIVE_SIZE != 0 {
            let padding_size = RECURSIVE_SIZE - (chunks.len() % RECURSIVE_SIZE);
            for _ in 0..padding_size {
                padded_nodes.push(Node::new(None));
            }
        }

        for chunk in chunks {
            let mut node = Node::new(None);

            node.set_children(chunk.to_vec());
            nodes.push(node);
        }

        // if there is only one node (and it is not the batch circuit), set it as the root
        if nodes.len() == 1 && !batch {
            Self {
                root: nodes[0].clone(),
                depth: depth + 1, // minimum depth is 2 --> 1 for the leafs and 1 for the root
            }
        } else {
            // otherwise, include the padding chunks and continue recursively generating the tree
            nodes.extend(padded_nodes);
            Self::new_from_leafs(nodes, depth + 1, false)
        }
    }

    pub fn get_nodes_from_depth(&mut self, depth: usize) -> Vec<&mut Node> {
        let mut result = Vec::new();

        self.root.collect_nodes_at_depth_mut(depth, &mut result, 1);
        result
    }

    //  NOT USED
    pub fn get_merkle_tree_exclude_leaves(&self) -> MerkleTree {
        let mut new_tree = self.clone();

        // get all the nodes a level before the leaves and exclude all children
        let nodes = new_tree.get_nodes_from_depth(self.depth - 1);

        // set the children of the nodes to None
        for node in nodes {
            node.children = None;
        }

        new_tree.depth -= 1;

        new_tree
    }

    pub fn get_nth_leaf_path(&self, n: usize) -> Option<Vec<usize>> {
        // get the leaf at the nth position

        let mut start_position = 0;
        let mut node_leafs;
        let mut current_node = &self.root;
        let mut path = Vec::new();

        for current_depth in 1..self.depth {
            // calculate what is the next node to enter
            node_leafs =
                RECURSIVE_SIZE.pow(self.depth as u32 - current_depth as u32 - 1) * BATCH_SIZE;

            // get the index of next node
            let index = (n - start_position) / node_leafs;

            current_node = &current_node.children.as_ref().unwrap()[index];
            start_position += index * node_leafs;

            path.push(index);
        }

        // get the leaf index at the nth position
        let leaf_index = n - start_position;
        path.push(leaf_index);

        // return the path
        if path.len() == self.depth {
            return Some(path);
        }

        None
    }

    fn verify_recursive(root_node: &Node) -> bool {
        // check if the node is a leaf
        if root_node.children.is_none() {
            return true;
        }

        // check if the node has children
        if let Some(ref children) = root_node.children {
            for child in children {
                // recursively verify each child
                Self::verify_recursive(child);
            }
        }

        // check if the node has a hash
        if root_node.hash.is_none() {
            return false;
        }

        // verify if the hash is the same as the hash of the children (Poseidon)
        let children_hashes = root_node
            .children
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|child| child.hash.clone())
            .collect::<Vec<_>>();

        let hash = hash_n_subhashes::<F, D>(&children_hashes).to_bytes();
        if root_node.hash.as_ref().unwrap() != &hash {
            return false;
        }

        true
    }

    pub fn verify(&self) -> bool {
        // check if the tree is a valid merkle tree
        Self::verify_recursive(&self.root)
    }

    pub fn prove_inclusion(&self, path: Vec<usize>) -> MerkleProof {
        // get the hashes from the left and right nodes
        let mut merkle_proof: Option<MerkleProof> = None;

        let mut current_node = &self.root;

        for i in 0..path.len() - 1 {
            // get the left and right hashes related to the leaf path node
            let index = path[i + 1]; // we use +1 to skip the root node (always 0 but it is included in the path)

            let nodes = current_node.children.as_ref().unwrap();
            let hashes = nodes
                .iter()
                .map(|node| node.hash.clone().unwrap())
                .collect::<Vec<_>>();

            // split the hashes into left and right using our index as pivot
            let left_hashes_temp = hashes[0..index].to_vec();
            let right_hashes_temp = hashes[index + 1..].to_vec();

            current_node = &nodes[index];

            if merkle_proof.is_none() {
                merkle_proof = Some(MerkleProof {
                    left_hashes: left_hashes_temp,
                    right_hashes: right_hashes_temp,
                    parent_hashes: None,
                });
            } else {
                merkle_proof = Some(MerkleProof {
                    left_hashes: left_hashes_temp,
                    right_hashes: right_hashes_temp,
                    parent_hashes: Some(Box::new(merkle_proof.unwrap())),
                });
            }
        }

        merkle_proof.unwrap()
    }
}
