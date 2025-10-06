import torch
from mrkle import MrkleTree


def namespaced_state_dict(model: torch.nn.Module) -> dict[str, torch.Tensor]:
    """
    Returns a state_dict with the model name prefixed to every key.
    """
    sd = model.state_dict()
    return {
        f"{model.__class__.__name__.lower()}.{k}": v.detach().cpu().numpy()
        for k, v in sd.items()
    }


class ToyModel(torch.nn.Module):
    def __init__(self, in_feature: int, out_feature: int):
        super().__init__()
        self.ln = torch.nn.Linear(in_feature, out_feature)
        self.output = torch.nn.Linear(out_feature, 1)

    def forward(self, x: torch.Tensor):
        x = self.ln(x)
        logits = self.output(torch.tanh(x))
        return logits, torch.sigmoid(x)


# Create model + state dict
model = ToyModel(10, 10)
state_dict = namespaced_state_dict(model)

# Construct Merkle tree over model parameters
tree = MrkleTree.from_dict(state_dict, name="sha256", fmt="flatten")

# Root hash identifies the entire model uniquely
if root := tree.root():
    print(root.hex())
