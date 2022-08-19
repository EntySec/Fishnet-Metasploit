"""
This plugin requires Fishnet: https://fishnet.com
Current source: https://github.com/EntySec/Fishnet
"""

from fishnet.lib.plugin import Plugin
from fishnet.lib.projects import Projects
from fishnet.lib.storage import Storage

from pex.string import StringTools

from pymetasploit3.msfrpc import MsfRpcClient


class FishnetPlugin(Plugin, Projects, Storage, StringTools):
    details = {
        'Name': 'Metasploit',
        'Category': 'network'
    }

    def sessions(self, project_uuid):
        sessions = self.msf.sessions.list
        sessions_db = self.sessions_db()

        if sessions:
            for session_id in sessions:
                if not sessions_db.filter(project=project_uuid).filter(
                        plugin=self.details['Name']
                ).filter(session=session_id).exists():
                    host = sessions[session_id]['Host']

                    if ipaddress.ip_address(host).is_private:
                        host = requests.get("https://myexternalip.com/json").json()['ip']

                    location = requests.get(f"http://ipinfo.io/{host}").json()

                    sessions_db.create(
                        project=project_uuid,
                        plugin=self.details['Name'],
                        session=session_id,
                        platform=sessions[session_id]['Platform'],
                        architecture=sessions[session_id]['Architecture'],
                        type=sessions[session_id]['Type'],
                        host=sessions[session_id]['Host'],
                        port=sessions[session_id]['Port'],
                        latitude=location['loc'].split(',')[0],
                        longitude=location['loc'].split(',')[1],
                        country=location['country']
                    )

        for session in sessions_db.all():
            if sessions:
                if session.session not in sessions:
                    sessions_db.filter(session=session.session).delete()
            else:
                sessions_db.filter(session=session.session).delete()

    def run(self, args):
        project_uuid = args['project_uuid']
        hosts_db = self.hosts_db()

        msfrpcd_password = self.random_string(8)
        os.system(f'msfrpcd -p {msfrpcd_password} -S')

        self.msf = MsfRpcClient(msfrpcd_password)

        while True:
            if not self.check_project_running(project_uuid):
                break

            hosts = hosts_db.filter(project=project_uuid)

            for host in hosts:
                self.scan(host, project_uuid)
