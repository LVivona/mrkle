from mrkle._mrkle_rs import errors

MerkleError = errors.MerkleError
ProofError = errors.ProofError
TreeError = errors.TreeError
NodeError = errors.NodeError
HashError = errors.HashError
SerdeError = errors.SerdeError


class HexDecoderError(BaseException):
    pass


class HexEncoderError(BaseException):
    pass
