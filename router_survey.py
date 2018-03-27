import rethinkdb as r
from rethinkdb.errors import RqlRuntimeError, RqlDriverError, RqlError, RqlTimeoutError
import paramiko
import logging
from datetime import datetime
from scp import SCPClient

localport = 28015

logging.basicConfig(level=logging.ERROR,
                    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    filename="/var/log/router_survey.log", filemode="a")

logger = logging.getLogger(__name__)


def createSSHClient(destination, user, k):

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(destination, port=22, username=user, pkey=k)
    return client


if __name__ == "__main__":


    host      = "ple1.cesnet.cz"
    username  = "upmc_kvermeulen"

    db_server = 'localhost'
    db_name   = "myops2"
    db_port   = localport
    c         = r.connect(db_server, db_port)

    pkey = paramiko.RSAKey.from_private_key_file("/home/kevin/.ssh/id_rsa")

    dossier_cree = False
    home = "/home/upmc_kvermeulen/"
    path = home + "MDAPROTOTYPE/"

    try:
        r.db(db_name).table_create("router_survey").run(c)
    except RqlRuntimeError:
        logger.info("table router_survey already exists")

    ip_s = []

    with open('hitlists/ple1.cesnet.cz_hitlist', 'r') as f:
        ip_s = [x.strip('\n') for x in f.readlines()]

    for dst in ip_s:
        try:
            ssh = createSSHClient(host, username, pkey)

            # Creating a directory where to put XML files
            if dossier_cree is False:
                stdin, stdout, stderr = ssh.exec_command('mkdir ' + path + host + '_xml')
                stdout.read()
                dossier_cree = True
                directory = path + host + '_xml'


            date = datetime.now()
            str_date = str(date)

            file_name = host + '_' + dst + '_' + str_date + '.xml'

            stdin, stdout, stderr = ssh.exec_command('cd ' + path + '; sudo python ' + '3phasesMda.py -o ' + "'" + file_name + "'" + ' ' + dst)
            stdout.read()
            stderr.read()
            stdin, stdout, stderr = ssh.exec_command('cd ' + path + '; sudo mv ' + "'" + path + file_name + "'" + ' ' + directory + '/')
            stdout.read()
            stdin, stdout, stderr = ssh.exec_command('cd ' + path + '; sudo mv ' + "'" + path + 'router_level_' + file_name + "'" + ' ' + directory + '/')
            stdout.read()

            scp = SCPClient(ssh.get_transport())
            scp.get(r'' + directory + '/' + file_name, r'/home/kevin/ROUTER_SURVEY/xml_files/')
            scp.get(r'' + directory + '/' + 'router_level_' + file_name, r'/home/kevin/ROUTER_SURVEY/xml_files/')

            stdin, stdout, stderr = ssh.exec_command('cd ' + path + '; sudo rm -f ' + directory + '/*')
            stdout.read()

        except paramiko.ssh_exception.AuthenticationException:
            print "Failed to connect to %s" % host

        else:
            ssh.close()



