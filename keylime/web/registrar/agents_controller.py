from keylime import keylime_logging
from keylime.models import RegistrarAgent
from keylime.web.base import Controller
import oqs
import base64

logger = keylime_logging.init_logging("registrar")

def verify_pq_signature(message, signature, signer_public_key):
    print(type(message), type(signature), type(signer_public_key))

    # Only encode if not already bytes
    encoded_message = message if isinstance(message, bytes) else bytes(message, encoding="utf-8")
    # encoded_signature = signature if isinstance(signature, bytes) else bytes(signature, encoding="utf-8")
    # encoded_key = signer_public_key if isinstance(signer_public_key, bytes) else bytes(signer_public_key, encoding="utf-8")
    sigalg = "ML-DSA-87"
    with oqs.Signature(sigalg) as signer:
        logger.debug("Public key length: %s", len(signer_public_key))
        logger.debug("Signature length: %s", len(signature))
        with oqs.Signature(sigalg) as verifier:
            is_valid = verifier.verify(encoded_message, signature, signer_public_key)
            if is_valid:
                logger.info("Signature verification successful")
            else:
                logger.info("Signature verification failed")
                # raise ValueError("Signature verification failed")
            return is_valid


class AgentsController(Controller):
    # GET /v2[.:minor]/agents/
    def index(self, **_params):
        results = RegistrarAgent.all_ids()

        self.respond(200, "Success", {"uuids": results})

    # GET /v2[.:minor]/agents/:agent_id/
    def show(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if not agent.active:
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", agent.render())

    # POST /v2[.:minor]/agents/[:agent_id]
    def create(self, agent_id, **params):
        agent = RegistrarAgent.get(agent_id) or RegistrarAgent.empty()  # type: ignore[no-untyped-call]
        agent.update({"agent_id": agent_id, **params})
        challenge = agent.produce_ak_challenge()

        if not challenge or not agent.changes_valid:
            self.log_model_errors(agent, logger)
            self.respond(400, "Could not register agent with invalid data")
            return

        agent.commit_changes()
        self.respond(200, "Success", {"blob": challenge})

    # DELETE /v2[.:minor]/agents/:agent_id/
    def delete(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        agent.delete()
        self.respond(200, "Success")

    # POST /v2[.:minor]/agents/:agent_id/[activate]
    def activate(self, agent_id, auth_tag, challenge_sig, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        accepted = agent.verify_ak_response(auth_tag)
        pq_key = agent.pq_key
        logger.info(f"pq_key = '{pq_key}'")
        logger.info(f"pq_key length = '{len(pq_key)}'")
        pq_key_bytes = base64.b64decode(pq_key)
        logger.info(f"pq_key_bytes = '{pq_key_bytes}'")
        logger.info(f"pq_key_bytes length = '{len(pq_key_bytes)}'") # 4627 B (expected value)
        pq_key_int_list = list(pq_key_bytes)
        logger.info(f"pq_key_int_list = '{pq_key_int_list}'")
        logger.info(f"pq_key_int_list length = '{len(pq_key_int_list)}'")
        logger.info(f"Size of challenge signature = '{len(challenge_sig)}'")
        # Convert the challenge signature to bytes
        challenge_sig_bytes = bytes(challenge_sig)
        logger.info(f"challenge_sig_bytes = '{challenge_sig_bytes}'")
        logger.info(f"challenge_sig_bytes length = '{len(challenge_sig_bytes)}'") # 4627 B (expected value)
        # convert the challenge signature to a string
        challenge_sig_b64 = base64.b64encode(challenge_sig_bytes).decode('ascii')
        logger.info(f"challenge_sig_b64 = '{challenge_sig_b64}'")
        logger.info(f"challenge_sig_b64 length = '{len(challenge_sig_b64)}'")
        result = verify_pq_signature(auth_tag, challenge_sig_bytes, pq_key_bytes)
        # if not result:
        #     self.respond(400, "Signature verification failed")
        #     return
        # logger.info(f"PQ Auth tag Signature verification result: {result}")
        if accepted:
            logger.info(type(agent))
            fields = vars(agent)
            #logger.info(fields)
            logger.info(type(auth_tag)) # str
            logger.info(type(pq_key)) # str
            logger.info(type(challenge_sig)) # list
            logger.info(f"Auth tag = '{auth_tag}'")
            logger.info(f"pq key = '{pq_key}'")
            #logger.info(f"Challenge signature = '{challenge_sig}'")
            logger.info("Authentication tag verified")
            logger.info("Agent activated")
            agent.commit_changes()
            self.respond(200, "Success")
        else:
            agent.delete()

            self.respond(
                400,
                f"Auth tag '{auth_tag}' for agent '{agent_id}' does not match expected value. The agent has been "
                f"deleted from the database and will need to be restarted to reattempt registration",
            )

