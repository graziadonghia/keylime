from keylime import keylime_logging
from keylime.models import RegistrarAgent
from keylime.web.base import Controller
import oqs
import os
import base64
import time
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
        challenge_sig_bytes = bytes(challenge_sig)
        t_start = time.perf_counter()
        result = verify_pq_signature(auth_tag, challenge_sig_bytes, pq_key_bytes, pq_algorithm)
        t_end = time.perf_counter()
        pq_verify_auth_ms = (t_end - t_start) * 1000
        # --- LOG TO CSV ---
        try:
            csv_path = "/tmp/registrar_metrics.csv"
            write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
            
            with open(csv_path, "a") as f:
                if write_header:
                    f.write("timestamp,agent_id,pq_algo,metric_type,duration_ms\n")
                
                now = int(time.time())
                # Log specifically as 'auth_verify'
                f.write(f"{now},{agent_id[:4]},{pq_algorithm},auth_verify,{pq_verify_auth_ms:.4f}\n")
        except Exception as e:
            logger.error(f"Failed to log metrics: {e}")
        # ------------------
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

