from keylime import keylime_logging
from keylime.models import RegistrarAgent
from keylime.web.base import Controller
import oqs
import base64
from keylime.crypto import verify_pq_signature

logger = keylime_logging.init_logging("registrar")

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
        pq_algorithm = agent.pq_algorithm
        pq_cert = agent.pq_cert
        logger.info(f"Using PQ algorithm: {pq_algorithm}")
        #logger.info(f"pq_key = '{pq_key}'")
        pq_key_bytes = base64.b64decode(pq_key)
        pq_key_int_list = list(pq_key_bytes)
        # logger.info(f"Size of MLDSA-87 signature of challenge = {len(challenge_sig)} B")
        # # Convert the challenge signature to bytes
        challenge_sig_bytes = bytes(challenge_sig)
        # # convert the challenge signature to a string
        # challenge_sig_b64 = base64.b64encode(challenge_sig_bytes).decode('ascii')
        result = verify_pq_signature(auth_tag, challenge_sig_bytes, pq_key_bytes, pq_algorithm)
        if not result:
            self.respond(400, "Signature verification failed")
            return
        logger.info(f"PQ Auth tag Signature verification result: {result}")
        if accepted:
            #logger.info(f"Auth tag = '{auth_tag}'")
            #logger.info(f"pq key = '{pq_key}'")
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

