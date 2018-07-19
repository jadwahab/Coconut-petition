const ISSUE_ERROR_NOT_ENOUGH_BALANCE = 'Balance was not high enough to issue the coin';
const ISSUE_ERROR_PROOF_INVALID = 'Proof of secret was invalid';
const ISSUE_SUCCESS = 'Coin was successfully issued';
const ISSUE_ERROR_INVALID_SIGNATURE = 'The signature on request was invalid';

export const ISSUE_STATUS = {
  error_balance: ISSUE_ERROR_NOT_ENOUGH_BALANCE,
  error_proof: ISSUE_ERROR_PROOF_INVALID,
  success: ISSUE_SUCCESS,
  error_signature: ISSUE_ERROR_INVALID_SIGNATURE,
};
