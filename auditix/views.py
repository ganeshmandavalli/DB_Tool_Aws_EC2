import os
import re
import subprocess
from datetime import datetime

import cx_Oracle  # For Oracle database connections
import django
import psycopg2  # For PostgreSQL connections
import pyodbc  # For Microsoft SQL Server connections
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render

# Set the correct settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SecureAuditix.settings")

# Initialize Django
django.setup()


def home(request):
    return render(request, 'index.html')  # Ensure 'index.html' exists in your templates directory

# Validation functions
def validate_input(input_value):
    pattern = r'^[a-zA-Z0-9._-]{1,25}$'
    return bool(re.match(pattern, input_value))


def validate_server(server):
    server_pattern = r'^[a-zA-Z0-9._-]+(,[0-9]{1,5})?$'
    return bool(re.match(server_pattern, server))


def validate_dsn(dsn_value):
    dsn_pattern = r'^[a-zA-Z0-9._-]+:\d{1,5}/[a-zA-Z0-9._-]+$'
    return bool(re.match(dsn_pattern, dsn_value))


# Main audit function
def audit_database(request):
    global settings  # Declare settings as global if needed
    if request.method == "POST":
        data = request.POST
        db_type = data.get("db_type")
        selected_standard = request.POST.get("audit_standard")
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        dsn = data.get("dsn", "").strip()
        server = data.get("server", "").strip()
        database = data.get("database", "").strip()

        # Input validation
        if not username or not validate_input(username):
            return JsonResponse({"error": "Invalid or missing Username."}, status=400)
        if not password or not validate_input(password):
            return JsonResponse({"error": "Invalid or missing Password."}, status=400)

        if db_type == "Oracle" and (not dsn or not validate_dsn(dsn)):
            return JsonResponse({"error": "Invalid or missing DSN for Oracle."}, status=400)
        elif db_type in ["MS SQL", "Postgresql"]:
            if not server or not validate_server(server):
                return JsonResponse({"error": "Invalid or missing Server."}, status=400)
            if not database or not validate_input(database):
                return JsonResponse({"error": "Invalid or missing Database."}, status=400)


        try:
            if db_type == "Oracle":
                # Connect to Oracle database
                connection = cx_Oracle.connect(username, password, dsn)
                # Create a cursor and execute a query
                cursor = connection.cursor()

                # Get the current date and time for the report
                current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Define file path inside Django's media directory
                file_name = "Oracle_Results.html"
                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                # Ensure MEDIA_ROOT exists
                os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

                with open(file_path, "w") as f:
                    f.write(f"""<html lang="en">
                                              <head>
                                                 <meta charset="UTF-8">
                                                 <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                                 <title>Audit Report</title>
                                                   <style>
                                                      body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                                      .header {{ text-align: right; font-size: 14px; margin-bottom: 10px; }}
                                                      .info-box {{ background-color: #f2f2f2; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }}
                                                       h2 {{ color: #00008B; text-align: center; margin-top: 20px; }}
                                                       h3 {{ color: #00008B; text-align: left; margin-top: 20px; }}
                                                       table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                                                       table, th, td {{ border: 1px solid #ddd; }}
                                                       th, td {{ padding: 12px; text-align: left; }}
                                                       th {{ background-color: #00008B; color: white; }}
                                                       tr:nth-child(even) {{ background-color: #f2f2f2; }}
                                                       .status-passed {{ color: green; }}
                                                       .status-failed {{ color: red; }}
                                                       .status-manual {{ color: black; }}
                                                       .status-nopermission {{ color: yellow; }}
                                                       .footer {{ text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0; }}
                                                       .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 10px; text-align: center; font-weight: bold; }}
                                                       .summary-table th {{ background-color: #00008B; color: white; }}
                                                   </style>
                                              </head>
                                                  <body>
                                                       <div class="header"><strong>Audit Date: </strong>{current_datetime}</div>
                                       """)

                    # Run the query for the CIS standard if selected
                    if selected_standard == "CIS":

                        # Execute the query
                        cursor.execute("SELECT banner AS version FROM v$version")

                        # Fetch the result
                        version_info = cursor.fetchall()

                        # Loop through the result and write it into the HTML file
                        for row in version_info:
                            f.write(f'''<div class="info-box">
                                            <p><strong>{row[0]}</strong><br> 
                                            </p> 
                                        </div>''')

                        # Count the pass, fail & Manual items.
                        Passed = 0
                        Failed = 0
                        Manual = 0
                        NoPermission = 0

                        f.write(f"<h2>Database Audit Report - CIS_Oracle_Database_19c_Benchmark_v1.2.0-1 </h2>")
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                          <strong>1. Oracle Database Installation and Patching Requirements</strong>  
                                      </p>''')

                        # Start the table
                        f.write('''<table>
                                                   <tr>
                                                    <th>Check</th>
                                                    <th>Status</th>
                                                   </tr>''')
                        # 1.1 Ensure the Appropriate Version/Patches for Oracle Software Is Installed (Manual)
                        f.write('''<tr>
                                                      <td>1.1 Ensure the Appropriate Version/Patches for Oracle Software Is Installed (Manual)</td>
                                                      <td class="status-manual">Manual</td>
                                                  </tr>''')
                        Manual += 1

                        # Close the first table
                        f.write("</table>")

                        # 2.Oracle Parameter Settings
                        # 2.1 Listener Settings
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                      <strong>2.Oracle Parameter Settings</strong>  
                                  </p>''')

                        f.write('''<p style="color: #00008B; font-size: 19px; text-align: left; margin-top: 19px;">
                                        <strong>2.1 Listener Settings</strong>  
                                  </p>''')

                        # Start the table
                        f.write('''<table>
                                      <tr>
                                          <th>Check</th>
                                          <th>Status</th>
                                      </tr>''')

                        # Define the path to listener.ora
                        oracle_home = os.environ.get('ORACLE_HOME')

                        # Check if ORACLE_HOME is not set
                        if oracle_home is None:
                            f.write('''<tr>
                                           <td>2.1.1 Ensure 'extproc' Is Not Present in 'listener.ora' (Automated)- ORACLE_HOME environment variable is not set </td>
                                           <td class="status-failed">Failed</td>
                                       </tr>''')
                            Failed += 1
                        else:
                            # Construct the path to listener.ora
                            listener_file_path = os.path.join(oracle_home, "network", "admin", "listener.ora")

                            # Check if listener.ora exists
                            if not os.path.exists(listener_file_path):
                                f.write(f'''<tr>
                                               <td>2.1.1 Ensure 'extproc' Is Not Present in 'listener.ora' (Automated)- listener.ora path not found. Please check the ORACLE_HOME path. </td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                # Open the listener.ora file and check if 'extproc' is present
                                try:
                                    with open(listener_file_path, 'r') as file:
                                        content = file.read()

                                    if 'extproc' in content:
                                        # If 'extproc' is found, write failure
                                        f.write(f'''<tr>
                                                       <td>2.1.1 Ensure 'extproc' Is Not Present in 'listener.ora' (Automated)- extproc found in listener_file_path. It should be removed </td>                            
                                                       <td class="status-failed">Failed</td>
                                                   </tr>''')
                                        Failed += 1
                                    else:
                                        # If 'extproc' is not found, write success
                                        f.write(f'''<tr>
                                                       <td>2.1.1 Ensure 'extproc' Is Not Present in 'listener.ora' (Automated)- extproc not present in listener_file_path</td>
                                                       <td class="status-passed">Passed</td>
                                                   </tr>''')

                                except Exception as e:
                                    # If there is an error opening the file, log failure and continue
                                    f.write(f'''<tr>
                                                   <td>2.1.1 Ensure 'extproc' Is Not Present in 'listener.ora' (Automated)- Error reading listener.ora file</td>
                                                   <td class="status-failed">Failed</td>
                                               </tr>''')
                                    NoPermission += 1

                        # 2.1.2 Ensure 'ADMIN_RESTRICTIONS_' Is Set to 'ON' (Automated)
                        if oracle_home is None:
                            f.write('''<tr>
                                           <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_<listener_name>' is Set to ON for All Listeners (Automated)- ORACLE_HOME environment variable is not set</td>
                                           <td class="status-failed">Failed</td>
                                       </tr>''')
                            Failed += 1
                        else:
                            # Check if listener.ora exists
                            if not os.path.exists(listener_file_path):
                                f.write(f'''<tr>
                                               <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_<listener_name>' is Set to ON for All Listeners (Automated)- listener.ora not found </td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                # Check for 'ADMIN_RESTRICTIONS_' in the listener.ora file
                                try:
                                    with open(listener_file_path, 'r') as file:
                                        content = file.read()

                                    if 'ADMIN_RESTRICTIONS_' in content:
                                        if 'ADMIN_RESTRICTIONS_ = ON' in content:
                                            # 'ADMIN_RESTRICTIONS_' is set to ON
                                            f.write(f'''<tr>
                                                           <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_' Is Set to 'ON' (Automated)- ADMIN_RESTRICTIONS_ is set to ON</td>
                                                           <td class="status-passed">Passed</td>
                                                       </tr>''')
                                        else:
                                            # 'ADMIN_RESTRICTIONS_' is present but not set to ON
                                            f.write(f'''<tr>
                                                           <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_' Is Set to 'ON' (Automated)- ADMIN_RESTRICTIONS_ is present but not set to ON</td>
                                                           <td class="status-failed">Failed</td>
                                                       </tr>''')
                                            Failed += 1
                                    else:
                                        # 'ADMIN_RESTRICTIONS_' is not present
                                        f.write(f'''<tr>
                                                       <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_<listener_name>' is Set to ON for All Listeners (Automated)- ADMIN_RESTRICTIONS_ not present in listener.ora</td>
                                                       <td class="status-failed">Failed</td>
                                                   </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle errors while reading the listener.ora file
                                    f.write(f'''<tr>
                                                   <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_<listener_name>' is Set to ON for All Listeners (Automated)- Error reading listener.ora file</td>
                                                   <td class="status-nopermission">NoPermission</td>
                                               </tr>''')
                                    NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 2.2 Database Settings
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                          <strong>2.2 Database Settings</strong>  
                                                      </p>''')

                        # Start the table
                        f.write('''<table>
                                        <tr>
                                            <th>Check</th>
                                            <th>Status</th>
                                        </tr>''')

                        # 2.2.1 Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'(Automated)
                        try:

                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                    SELECT UPPER(VALUE)
                                    FROM V$SYSTEM_PARAMETER
                                    WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS'
                                """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is TRUE
                            if result and result[0] == 'TRUE':
                                f.write('''<tr>
                                               <td>2.2.1 Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'(Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                                <td>2.2.1 Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'(Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Display error if connection fails
                            f.write('''<tr>
                                          <td>2.1.2 Ensure 'ADMIN_RESTRICTIONS_<listener_name>' is Set to ON for All Listeners (Automated)- Error reading listener.ora file</td>
                                           <td class="status-nopermission">NoPermission</td>
                                        </tr>''')
                            NoPermission += 1

                        # 2.2.2 Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'AUDIT_TRAIL'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is one of the acceptable values
                            acceptable_values = ['DB', 'XML', 'OS', 'DB,EXTENDED', 'XML,EXTENDED']

                            if result and result[0] in acceptable_values:
                                f.write('''<tr>
                                               <td>2.2.2 Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.2 Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Display error if connection fails
                            f.write('''<tr>
                                           <td>2.2.2 Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED' (Automated) - Error executing query</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.3 Ensure 'GLOBAL_NAMES' Is Set to 'TRUE' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT DISTINCT UPPER(V.VALUE),
                                DECODE (V.CON_ID, 
                                        0, (SELECT NAME FROM V$DATABASE),
                                        1, (SELECT NAME FROM V$DATABASE),
                                        (SELECT NAME FROM V$PDBS B WHERE V.CON_ID = B.CON_ID))
                                FROM V$SYSTEM_PARAMETER V
                                WHERE UPPER(NAME) = 'GLOBAL_NAMES'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the value is TRUE
                            if result and result[0] == 'TRUE':
                                f.write('''<tr>
                                               <td>2.2.3 Ensure 'GLOBAL_NAMES' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.3 Ensure 'GLOBAL_NAMES' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Display error if connection fails
                            f.write('''<tr>
                                           <td>2.2.3 Ensure 'GLOBAL_NAMES' Is Set to 'TRUE' (Automated) - Error executing query</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.4 Ensure 'OS_ROLES' Is Set to 'FALSE' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT DISTINCT UPPER(V.VALUE),
                                DECODE(V.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE V.CON_ID = B.CON_ID))
                                FROM V$SYSTEM_PARAMETER V
                                WHERE UPPER(NAME) = 'OS_ROLES'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result[0] is 'FALSE' for 'OS_ROLES'
                            if result and result[0] == 'FALSE':
                                f.write('''<tr>
                                               <td>2.2.4 Ensure 'OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.4 Ensure 'OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.4 Ensure 'OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 2.2.5 Ensure 'REMOTE_LISTENER' Is Empty (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT DISTINCT UPPER(V.VALUE),
                                DECODE(V.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE V.CON_ID = B.CON_ID))
                                FROM V$SYSTEM_PARAMETER V
                                WHERE UPPER(NAME) = 'REMOTE_LISTENER' AND VALUE IS NOT NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Check if results are empty for 'REMOTE_LISTENER'
                            if not results:
                                f.write('''<tr>
                                               <td>2.2.5 Ensure 'REMOTE_LISTENER' Is Empty (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.5 Ensure 'REMOTE_LISTENER' Is Empty (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.5 Ensure 'REMOTE_LISTENER' Is Empty (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.6 Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'REMOTE_LOGIN_PASSWORDFILE'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is 'NONE' or 'EXCLUSIVE'
                            if result and (result[0] == 'NONE' or result[0] == 'EXCLUSIVE'):
                                f.write('''<tr>
                                               <td>2.2.6 Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.6 Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.6 Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 2.2.7 Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'REMOTE_OS_AUTHENT'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is 'FALSE'
                            if result and result[0] == 'FALSE':
                                f.write('''<tr>
                                               <td>2.2.7 Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.7 Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.7 Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'REMOTE_OS_ROLES'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # 2.2.8 Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE' (Automated)
                            # Check if the result is 'FALSE'
                            if result and result[0] == 'FALSE':
                                f.write('''<tr>
                                               <td>2.2.8 Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.8 Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.8 Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.9 Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'SEC_CASE_SENSITIVE_LOGON'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is 'TRUE'
                            if result and result[0] == 'TRUE':
                                f.write('''<tr>
                                               <td>2.2.9 Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.9 Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.9 Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'SEC_MAX_FAILED_LOGIN_ATTEMPTS'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # 2.2.10 Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '3' or Less (Automated)
                            # Check if the result is '3' or less
                            if result and int(result[0]) <= 3:
                                f.write('''<tr>
                                               <td>2.2.10 Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '3' or Less (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.10 Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '3' or Less (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.10 Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '3' or Less (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.11 Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to '(DROP,3)' (Automated)

                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'SEC_PROTOCOL_ERROR_FURTHER_ACTION'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is '(DROP,3)' or '(DROP, 3)'
                            if result and (result[0] == '(DROP,3)' or result[0] == '(DROP, 3)'):
                                f.write('''<tr>
                                               <td>2.2.11 Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to Audit (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.11 Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to Audit (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.11 Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to Audit (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 2.2.12 Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG' (Automated)
                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'SEC_PROTOCOL_ERROR_TRACE_ACTION'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # Check if the result is 'LOG'
                            if result and result[0] == 'LOG':
                                f.write('''<tr>
                                               <td>2.2.12 Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.12 Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.12 Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        try:
                            # Create a cursor and execute the query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'SEC_RETURN_SERVER_RELEASE_BANNER'
                            """)

                            # Fetch the result
                            result = cursor.fetchone()

                            # 2.2.13 Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' (Automated)

                            # Check if the result is 'FALSE'
                            if result and result[0] == 'FALSE':
                                f.write('''<tr>
                                               <td>2.2.13 Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.13 Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.13 Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT DISTINCT UPPER(V.VALUE),
                                DECODE(V.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE V.CON_ID = B.CON_ID))
                                FROM V$SYSTEM_PARAMETER V
                                WHERE UPPER(NAME) = 'SQL92_SECURITY'
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize flags for pass/fail
                            all_passed = True

                            # Check if any of the results is not 'TRUE'
                            for result in results:
                                if result[0] != 'TRUE':
                                    all_passed = False
                                    break

                            if all_passed:
                                f.write('''<tr>
                                               <td>2.2.14 Ensure 'SQL92_SECURITY' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.14 Ensure 'SQL92_SECURITY' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>2.2.14 Ensure 'SQL92_SECURITY' Is Set to 'TRUE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.15 Ensure '_trace_files_public' Is Set to 'FALSE' (Automated)

                        try:
                            # Create a cursor and execute the query to check '_trace_files_public'
                            cursor = connection.cursor()
                            cursor.execute("""
                                              SELECT A.KSPPINM, B.KSPPSTVL
                                              FROM SYS.X_$KSPPI A
                                              JOIN SYS.X_$KSPPCV B ON A.INDX = B.INDX
                                              WHERE A.KSPPINM LIKE '\_%trace_files_public' ESCAPE '\';
                                               """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize flags for pass/fail
                            compliance = False

                            # Check the results for compliance
                            if results:
                                for result in results:
                                    if result[1] == 'FALSE':  # Check if the parameter value is 'FALSE'
                                        compliance = True
                                        break

                            # Log the results
                            if compliance:
                                f.write('''<tr>
                                              <td>2.2.15 Ensure '_trace_files_public' Is Set to 'FALSE' (Automated)</td>
                                              <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                                <td>2.2.15 Ensure '_trace_files_public' Is Set to 'FALSE' (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                            <td>2.2.15 Ensure '_trace_files_public' Is Set to 'FALSE' (Automated)</td>
                                            <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.16 Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' (Automated)

                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT DISTINCT UPPER(V.VALUE),
                                DECODE(V.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE V.CON_ID = B.CON_ID))
                                FROM V$SYSTEM_PARAMETER V
                                WHERE UPPER(NAME) = 'RESOURCE_LIMIT'
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize flags for pass/fail
                            all_passed = True

                            # Check if any of the results is not 'TRUE'
                            for result in results:
                                if result[0] != 'TRUE':
                                    all_passed = False
                                    break

                            # Write the result to the HTML file based on the check
                            if all_passed:
                                f.write('''<tr>
                                               <td>2.2.16 Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>2.2.16 Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>2.2.16 Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 2.2.17Ensure 'PDB_OS_CREDENTIAL' is NOT null (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()
                            cursor.execute("""
                                SELECT UPPER(VALUE)
                                FROM V$SYSTEM_PARAMETER
                                WHERE UPPER(NAME) = 'PDB_OS_CREDENTIAL' AND VALUE IS NOT NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Check if any rows are returned
                            if not results:
                                # Passed if no rows are returned (compliant)
                                f.write('''<tr>
                                               <td>2.2.17 Ensure 'PDB_OS_CREDENTIAL' is NOT null (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if there are any rows returned (non-compliant)
                                f.write('''<tr>
                                               <td>2.2.17 Ensure 'PDB_OS_CREDENTIAL' is NOT null (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>2.2.17 Ensure 'PDB_OS_CREDENTIAL' is NOT null (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 2.3 SQLNET.ORA Settings

                        f.write('''<p style="color: #00008B; font-size: 19px; text-align: left; margin-top: 19px;">
                                                            <strong>2.3 SQLNET.ORA Settings</strong>  
                                                      </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                              <th>Check</th>
                                              <th>Status</th>
                                          </tr>''')

                        # 2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - Windows
                        # Define the path to sqlnet.ora
                        oracle_home = os.environ.get('ORACLE_HOME')

                        # Check if ORACLE_HOME is not set
                        if oracle_home is None:
                            f.write('''<tr>
                                           <td>2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - ORACLE_HOME environment variable is not set</td>
                                           <td class="status-failed">Failed</td>
                                       </tr>''')
                            Failed += 1
                        else:
                            # Construct the path to sqlnet.ora
                            sqlnet_file_path = os.path.join(oracle_home, "network", "admin", "sqlnet.ora")

                            # Check if sqlnet.ora exists
                            if not os.path.exists(sqlnet_file_path):
                                f.write(f'''<tr>
                                               <td>2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - sqlnet.ora path not found. Please check the ORACLE_HOME path.</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                # Open the sqlnet.ora file and check if 'encryption_server=required' is present
                                try:
                                    with open(sqlnet_file_path, 'r') as file:
                                        content = file.read()

                                    if 'encryption_server=required' in content:
                                        # If 'encryption_server=required' is found, write success
                                        f.write(f'''<tr>
                                                       <td>2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - encryption_server=required is present in sqlnet.ora</td>
                                                       <td class="status-passed">Passed</td>
                                                   </tr>''')
                                        Passed += 1
                                    else:
                                        # If 'encryption_server=required' is not found, write failure
                                        f.write(f'''<tr>
                                                       <td>2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - encryption_server=required not found in sqlnet.ora. It should be set to 'required'</td>
                                                       <td class="status-failed">Failed</td>
                                                   </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # If there is an error opening the file, log failure and continue
                                    f.write(f'''<tr>
                                                   <td>2.3.1 Ensure 'ENCRYPTION_SERVER' Is Set to 'REQUIRED' (Automated) - Error reading sqlnet.ora file</td>
                                                   <td class="status-failed">Failed</td>
                                               </tr>''')
                                    NoPermission += 1

                        # 2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) (Automated)

                        # Define the path to sqlnet.ora
                        oracle_home = os.environ.get('ORACLE_HOME')

                        # Check if ORACLE_HOME is not set
                        if oracle_home is None:
                            f.write('''<tr>
                                           <td>2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) - ORACLE_HOME environment variable is not set</td>
                                           <td class="status-failed">Failed</td>
                                       </tr>''')
                            Failed += 1
                        else:
                            # Construct the path to sqlnet.ora
                            sqlnet_file_path = os.path.join(oracle_home, "network", "admin", "sqlnet.ora")

                            # Check if sqlnet.ora exists
                            if not os.path.exists(sqlnet_file_path):
                                f.write(f'''<tr>
                                               <td>2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) - sqlnet.ora path not found. Please check the ORACLE_HOME path.</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                # Open the sqlnet.ora file and check if 'crypto_checksum_server=required' is present
                                try:
                                    with open(sqlnet_file_path, 'r') as file:
                                        content = file.read()

                                    if 'crypto_checksum_server=required' in content:
                                        # If 'crypto_checksum_server=required' is found, write success
                                        f.write(f'''<tr>
                                                       <td>2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) - crypto_checksum_server=required is present in sqlnet.ora</td>
                                                       <td class="status-passed">Passed</td>
                                                   </tr>''')
                                        Passed += 1
                                    else:
                                        # If 'crypto_checksum_server=required' is not found, write failure
                                        f.write(f'''<tr>
                                                       <td>2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) - crypto_checksum_server=required not found in sqlnet.ora. It should be set to 'required'</td>
                                                       <td class="status-failed">Failed</td>
                                                   </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # If there is an error opening the file, log failure and continue
                                    f.write(f'''<tr>
                                                   <td>2.3.2 Ensure 'SQLNET.CRYPTO_CHECKSUM_SERVER' Is Set to 'REQUIRED' (Automated) - Error reading sqlnet.ora file</td>
                                                   <td class="status-failed">Failed</td>
                                               </tr>''')
                                    NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 3. Oracle Connection and Login Restrictions
                        # 3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' (Automated)
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                          <strong>3. Oracle Connection and Login Restrictions</strong>  
                                                      </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                               <th>Check</th>
                                               <th>Status</th>
                                           </tr>''')

                        # 3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
                                1,(SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT',(SELECT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'
                                AND CON_ID = P.CON_ID),
                                'UNLIMITED','9999',P.LIMIT)) > 5
                                AND P.RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
                                AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'),
                                'UNLIMITED','9999',P.LIMIT)) > 5
                                AND P.RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
                                AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if any profile exceeds 5 failed login attempts
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) > 5:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if no profiles exceed 5 failed login attempts
                                f.write('''<tr>
                                               <td>3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile exceeds 5 failed login attempts
                                f.write('''<tr>
                                               <td>3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.2 Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_LOCK_TIME'
                                AND CON_ID = P.CON_ID),
                                'UNLIMITED', '9999', P.LIMIT)) < 1
                                AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DISTINCT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_LOCK_TIME'),
                                'UNLIMITED', '9999', P.LIMIT)) < 1
                                AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if results are empty
                            if not results:  # If no results are returned
                                all_compliant = False  # Set to fail since no profiles were found

                            # Check if any profile has PASSWORD_LOCK_TIME less than 1
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) < 1:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_LOCK_TIME >= 1
                                f.write('''<tr>
                                               <td>3.2 Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_LOCK_TIME < 1 or if there are no results
                                f.write('''<tr>
                                               <td>3.2 Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.2 Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.3 Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE = 'DEFAULT'
                                AND RESOURCE_NAME = 'PASSWORD_LIFE_TIME' AND CON_ID = P.CON_ID),
                                'UNLIMITED', '9999', P.LIMIT)) > 90
                                AND P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DISTINCT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE = 'DEFAULT'
                                AND RESOURCE_NAME = 'PASSWORD_LIFE_TIME'),
                                'UNLIMITED', '9999', P.LIMIT)) > 90
                                AND P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if any profile has PASSWORD_LIFE_TIME greater than 90
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) > 90:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_LIFE_TIME <= 90
                                f.write('''<tr>
                                               <td>3.3 Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_LIFE_TIME > 90
                                f.write('''<tr>
                                               <td>3.3 Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.3 Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.4 Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_REUSE_MAX'
                                AND CON_ID = P.CON_ID),
                                'UNLIMITED', '9999', P.LIMIT)) < 20
                                AND P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DISTINCT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_REUSE_MAX'),
                                'UNLIMITED', '9999', P.LIMIT)) < 20
                                AND P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if results are empty
                            if not results:  # If no results are returned
                                all_compliant = False  # Set to fail since no profiles were found

                            # Check if any profile has PASSWORD_REUSE_MAX less than 20
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) < 20:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_REUSE_MAX >= 20
                                f.write('''<tr>
                                               <td>3.4 Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_REUSE_MAX < 20 or if there are no results
                                f.write('''<tr>
                                               <td>3.4 Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.4 Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.5 Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_REUSE_TIME'
                                AND CON_ID = P.CON_ID),
                                'UNLIMITED', '9999', P.LIMIT)) < 365
                                AND P.RESOURCE_NAME = 'PASSWORD_REUSE_TIME'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DISTINCT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_REUSE_TIME'),
                                'UNLIMITED', '9999', P.LIMIT)) < 365
                                AND P.RESOURCE_NAME = 'PASSWORD_REUSE_TIME'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if results are empty
                            if not results:  # If no results are returned
                                all_compliant = False  # Set to fail since no profiles were found

                            # Check if any profile has PASSWORD_REUSE_TIME less than 365
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) < 365:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_REUSE_TIME >= 365
                                f.write('''<tr>
                                               <td>3.5 Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_REUSE_TIME < 365 or if there are no results
                                f.write('''<tr>
                                               <td>3.5 Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.5 Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.6  Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5' (Automated)

                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM CDB_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_GRACE_TIME'
                                AND CON_ID = P.CON_ID),
                                'UNLIMITED', '9999', P.LIMIT)) > 5
                                AND P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE TO_NUMBER(DECODE(P.LIMIT,
                                'DEFAULT', (SELECT DISTINCT DECODE(LIMIT, 'UNLIMITED', 9999, LIMIT)
                                FROM DBA_PROFILES WHERE PROFILE='DEFAULT'
                                AND RESOURCE_NAME='PASSWORD_GRACE_TIME'),
                                'UNLIMITED', '9999', P.LIMIT)) > 5
                                AND P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if results are empty
                            if not results:  # If no results are returned
                                all_compliant = True  # Set to pass since no profiles were found

                            # Check if any profile has PASSWORD_GRACE_TIME greater than 5
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is not None and limit != 'UNLIMITED' and int(limit) > 5:
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_GRACE_TIME <= 5
                                f.write('''<tr>
                                               <td>3.6 Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_GRACE_TIME > 5
                                f.write('''<tr>
                                               <td>3.6 Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.6 Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.7 Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles (Automated)

                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE (P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                1, (SELECT NAME FROM V$DATABASE),
                                (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE DECODE(P.LIMIT,
                                'DEFAULT', (SELECT LIMIT FROM CDB_PROFILES
                                WHERE PROFILE='DEFAULT' AND RESOURCE_NAME = P.RESOURCE_NAME AND CON_ID = P.CON_ID),
                                LIMIT) = 'NULL'
                                AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                                ORDER BY CON_ID, PROFILE, RESOURCE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE DECODE(P.LIMIT,
                                'DEFAULT', (SELECT LIMIT FROM DBA_PROFILES
                                WHERE PROFILE='DEFAULT' AND RESOURCE_NAME = P.RESOURCE_NAME),
                                LIMIT) = 'NULL'
                                AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for pass/fail
                            all_compliant = True

                            # Check if results are empty
                            if not results:  # If no results are returned
                                all_compliant = True  # Set to pass since no profiles were found

                            # Check if any profile has PASSWORD_VERIFY_FUNCTION set to NULL
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set
                                if limit is None or limit == 'NULL':
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have PASSWORD_VERIFY_FUNCTION set
                                f.write('''<tr>
                                               <td>3.7 Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has PASSWORD_VERIFY_FUNCTION set to NULL
                                f.write('''<tr>
                                               <td>3.7 Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.7 Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.8 Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '10' (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE(P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE P.RESOURCE_NAME = 'SESSIONS_PER_USER'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE P.RESOURCE_NAME = 'SESSIONS_PER_USER'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for compliance check
                            all_compliant = True

                            # Check if any profile has SESSIONS_PER_USER greater than 10 or is UNLIMITED
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set

                                # Check if limit is NULL, UNLIMITED or greater than 10
                                if limit is None or limit == 'UNLIMITED' or (limit != 'DEFAULT' and int(limit) > 10):
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have SESSIONS_PER_USER set to 10 or less
                                f.write('''<tr>
                                               <td>3.8 Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '10' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has SESSIONS_PER_USER greater than 10, UNLIMITED or NULL
                                f.write('''<tr>
                                               <td>3.8 Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '10' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.8 Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '10' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 3.9 Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120' (Automated)

                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT DISTINCT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
                                DECODE(P.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE P.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_PROFILES P
                                WHERE P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
                                AND EXISTS (SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
                                FROM DBA_PROFILES P
                                WHERE P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
                                AND EXISTS (SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE)
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Initialize flag for compliance check
                            all_compliant = True

                            # Check if any profile has INACTIVE_ACCOUNT_TIME greater than 120 or is NULL
                            for result in results:
                                limit = result[2]  # Extract the LIMIT value from the result set

                                # Check if limit is NULL, UNLIMITED or greater than 120
                                if limit is None or limit == 'UNLIMITED' or (limit != 'DEFAULT' and int(limit) > 120):
                                    all_compliant = False
                                    break

                            # Determine if the test passed or failed
                            if all_compliant:
                                # Passed if all profiles have INACTIVE_ACCOUNT_TIME set to 120 or less
                                f.write('''<tr>
                                               <td>3.9 Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120' (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any profile has INACTIVE_ACCOUNT_TIME greater than 120, UNLIMITED or NULL
                                f.write('''<tr>
                                               <td>3.9 Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120' (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>3.9 Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120' (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 4. Users
                        # 4.1 Ensure All Default Passwords Are Changed (Automated)

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                       <strong>4. Users</strong>  
                                   </p>''')

                        # Start the table
                        f.write('''<table>
                                           <tr>
                                           <th>Check</th>
                                           <th>Status</th>
                                        </tr>''')

                        # 4.1 Ensure All Default Passwords Are Changed (Automated)

                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT DISTINCT A.USERNAME,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_USERS_WITH_DEFPWD A, CDB_USERS C
                                WHERE A.USERNAME = C.USERNAME
                                AND C.ACCOUNT_STATUS = 'OPEN'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT DISTINCT A.USERNAME
                                FROM DBA_USERS_WITH_DEFPWD A, DBA_USERS B
                                WHERE A.USERNAME = B.USERNAME
                                AND B.ACCOUNT_STATUS = 'OPEN'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.1 Ensure All Default Passwords Are Changed (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if there are users with default passwords
                                f.write('''<tr>
                                               <td>4.1 Ensure All Default Passwords Are Changed (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1



                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.1 Ensure All Default Passwords Are Changed (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 4.2 Ensure All Sample Data and Users Have Been Removed (Automated)
                        try:
                            # Create a cursor and execute the multi-tenant query
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT DISTINCT A.USERNAME,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_USERS A
                                WHERE A.USERNAME IN ('BI', 'HR', 'IX', 'OE', 'PM', 'SCOTT', 'SH')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT USERNAME
                                FROM DBA_USERS
                                WHERE USERNAME IN ('BI', 'HR', 'IX', 'OE', 'PM', 'SCOTT', 'SH')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.2 Ensure All Sample Data And Users Have Been Removed (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if there are sample users present
                                f.write('''<tr>
                                               <td>4.2 Ensure All Sample Data And Users Have Been Removed (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.2 Ensure All Sample Data And Users Have Been Removed (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 4.3 Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for Any User (Automated)
                        try:
                            # Create a cursor for database connection
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT A.USERNAME,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_USERS A
                                WHERE AUTHENTICATION_TYPE = 'EXTERNAL'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT USERNAME
                                FROM DBA_USERS
                                WHERE AUTHENTICATION_TYPE = 'EXTERNAL'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.3 Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for Any User (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if there are users with AUTHENTICATION_TYPE = 'EXTERNAL'
                                f.write('''<tr>
                                               <td>4.3 Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for Any User (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.3 Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for Any User (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 4.4 Ensure No Users Are Assigned the 'DEFAULT' Profile (Automated)

                        try:
                            # Create a cursor for database connection
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT A.USERNAME,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_USERS A
                                WHERE A.PROFILE = 'DEFAULT'
                                AND A.ACCOUNT_STATUS = 'OPEN'
                                AND A.ORACLE_MAINTAINED = 'N'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT USERNAME
                                FROM DBA_USERS
                                WHERE PROFILE = 'DEFAULT'
                                AND ACCOUNT_STATUS = 'OPEN'
                                AND ORACLE_MAINTAINED = 'N'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.4 Ensure No Users Are Assigned the 'DEFAULT' Profile (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if there are users with the DEFAULT profile
                                f.write('''<tr>
                                               <td>4.4 Ensure No Users Are Assigned the 'DEFAULT' Profile (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.4 Ensure No Users Are Assigned the 'DEFAULT' Profile (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 4.5 Ensure 'SYS.USER$MIG' Has Been Dropped (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT OWNER, TABLE_NAME,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TABLES A
                                WHERE TABLE_NAME = 'USER$MIG' AND OWNER = 'SYS'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT OWNER, TABLE_NAME
                                FROM DBA_TABLES
                                WHERE TABLE_NAME = 'USER$MIG' AND OWNER = 'SYS'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.5 Ensure 'SYS.USER$MIG' Has Been Dropped (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if the SYS.USER$MIG table exists
                                f.write('''<tr>
                                               <td>4.5 Ensure 'SYS.USER$MIG' Has Been Dropped (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.5 Ensure 'SYS.USER$MIG' Has Been Dropped (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 4.6 Ensure No Public Database Links Exist (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT DB_LINK, HOST,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_DB_LINKS A
                                WHERE OWNER = 'PUBLIC'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT DB_LINK, HOST
                                FROM DBA_DB_LINKS
                                WHERE OWNER = 'PUBLIC'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>4.6 Ensure No Public Database Links Exist (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if public database links exist
                                f.write('''<tr>
                                               <td>4.6 Ensure No Public Database Links Exist (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>4.6 Ensure No Public Database Links Exist (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 5. Privileges & Grants & ACLs
                        # 5.1 Excessive Table, View and Package Privileges
                        # 5.1.1 Public Privileges

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                 <strong>5. Privileges & Grants & ACLs</strong>  
                                    </p>''')
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                <strong> 5.1 Excessive Table, View and Package Privileges</strong>  
                                   </p>''')
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                 <strong>5.1.1 Public Privileges</strong>  
                                    </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                              <th>Check</th>
                                              <th>Status</th>
                                          </tr>''')

                        # 5.1.1.1 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "Network" Packages (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of network packages
                            network_packages = ['DBMS_LDAP', 'UTL_INADDR', 'UTL_TCP', 'UTL_MAIL', 'UTL_SMTP',
                                                'UTL_DBWS', 'UTL_ORAMTS', 'UTL_HTTP', 'HTTPURITYPE']

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in network_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in network_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.1 Ensure "EXECUTE" is revoked from "PUBLIC" on "Network" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.1 Ensure "EXECUTE" is revoked from "PUBLIC" on "Network" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.1 Ensure "EXECUTE" is revoked from "PUBLIC" on "Network" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.2 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "FileSystem" Packages (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of file system packages
                            file_system_packages = ['DBMS_ADVISOR', 'DBMS_LOB', 'UTL_FILE']

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in file_system_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in file_system_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.2 Ensure "EXECUTE" is revoked from "PUBLIC" on "File System" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.2 Ensure "EXECUTE" is revoked from "PUBLIC" on "File System" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.2 Ensure "EXECUTE" is revoked from "PUBLIC" on "File System" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.3 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "Encryption" Packages (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of encryption packages
                            encryption_packages = ['DBMS_CRYPTO', 'DBMS_OBFUSCATION_TOOLKIT', 'DBMS_RANDOM']

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in encryption_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in encryption_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.3 Ensure "EXECUTE" is revoked from "PUBLIC" on "Encryption" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.3 Ensure "EXECUTE" is revoked from "PUBLIC" on "Encryption" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.3 Ensure "EXECUTE" is revoked from "PUBLIC" on "Encryption" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.4 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "Java" Packages (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of Java packages
                            java_packages = ['DBMS_JAVA', 'DBMS_JAVA_TEST']

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in java_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in java_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.4 Ensure "EXECUTE" is revoked from "PUBLIC" on "Java" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.4 Ensure "EXECUTE" is revoked from "PUBLIC" on "Java" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.4 Ensure "EXECUTE" is revoked from "PUBLIC" on "Java" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.5 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "Job Scheduler" Packages (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of Job Scheduler packages
                            scheduler_packages = ['DBMS_SCHEDULER', 'DBMS_JOB']

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in scheduler_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in scheduler_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.5 Ensure "EXECUTE" is revoked from "PUBLIC" on "Job Scheduler" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.5 Ensure "EXECUTE" is revoked from "PUBLIC" on "Job Scheduler" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.5 Ensure "EXECUTE" is revoked from "PUBLIC" on "Job Scheduler" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.6 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "SQL Injection Helper" Packages (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # List of SQL Injection Helper packages
                            sql_injection_helper_packages = [
                                'DBMS_SQL', 'DBMS_XMLGEN', 'DBMS_XMLQUERY', 'DBMS_XMLSTORE',
                                'DBMS_XMLSAVE', 'DBMS_AW', 'OWA_UTIL', 'DBMS_REDIRECT'
                            ]

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in sql_injection_helper_packages)})
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute(f"""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN ({','.join("'" + p + "'" for p in sql_injection_helper_packages)})
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_multi + results_non_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.6 Ensure "EXECUTE" is revoked from "PUBLIC" on "SQL Injection Helper" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the listed packages
                                f.write('''<tr>
                                               <td>5.1.1.6 Ensure "EXECUTE" is revoked from "PUBLIC" on "SQL Injection Helper" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.6 Ensure "EXECUTE" is revoked from "PUBLIC" on "SQL Injection Helper" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.1.7 Ensure 'EXECUTE' is revoked from 'PUBLIC' on "DBMS_CREDENTIAL" Package (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME = 'DBMS_CREDENTIAL'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                       1, (SELECT NAME FROM V$DATABASE),
                                       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME = 'DBMS_CREDENTIAL'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.1.7 Ensure "EXECUTE" is revoked from "PUBLIC" on "DBMS_CREDENTIAL" Package</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the DBMS_CREDENTIAL package
                                f.write('''<tr>
                                               <td>5.1.1.7 Ensure "EXECUTE" is revoked from "PUBLIC" on "DBMS_CREDENTIAL" Package</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.1.7 Ensure "EXECUTE" is revoked from "PUBLIC" on "DBMS_CREDENTIAL" Package</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 5.1.2 Non-Default Privileges

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                     <strong>5.1.2 Non-Default Privileges</strong>  
                                   </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                              <th>Check</th>
                                              <th>Status</th>
                                          </tr>''')

                        # 5.1.2.1 Ensure "EXECUTE" is not granted to "PUBLIC" on "Non-default" Packages

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE
                                FROM DBA_TAB_PRIVS
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN (
                                    'DBMS_BACKUP_RESTORE',
                                    'DBMS_FILE_TRANSFER',
                                    'DBMS_SYS_SQL',
                                    'DBMS_REPCAT_SQL_UTL',
                                    'INITJVMAUX',
                                    'DBMS_AQADM_SYS',
                                    'DBMS_STREAMS_RPC',
                                    'DBMS_PRVTAQIM',
                                    'LTADM',
                                    'DBMS_IJOB',
                                    'DBMS_PDB_EXEC_SQL'
                                )
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE GRANTEE = 'PUBLIC'
                                AND PRIVILEGE = 'EXECUTE'
                                AND TABLE_NAME IN (
                                    'DBMS_BACKUP_RESTORE',
                                    'DBMS_FILE_TRANSFER',
                                    'DBMS_SYS_SQL',
                                    'DBMS_REPCAT_SQL_UTL',
                                    'INITJVMAUX',
                                    'DBMS_AQADM_SYS',
                                    'DBMS_STREAMS_RPC',
                                    'DBMS_PRVTAQIM',
                                    'LTADM',
                                    'DBMS_IJOB',
                                    'DBMS_PDB_EXEC_SQL'
                                )
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.2.1 Ensure "EXECUTE" is not granted to "PUBLIC" on "Non-default" Packages</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if EXECUTE privilege exists for PUBLIC on the Non-default packages
                                f.write('''<tr>
                                               <td>5.1.2.1 Ensure "EXECUTE" is not granted to "PUBLIC" on "Non-default" Packages</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.2.1 Ensure "EXECUTE" is not granted to "PUBLIC" on "Non-default" Packages</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 5.1.3 Other Privileges

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                <strong>5.1.3 Other Privileges</strong>  
                                   /p>''')

                        # Start the table
                        f.write('''<table>
                                         <tr>
                                             <th>Check</th>
                                             <th>Status</th>
                                        </tr>''')
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_TAB_PRIVS
                                WHERE TABLE_NAME = 'AUD$'
                                AND OWNER = 'SYS'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE TABLE_NAME = 'AUD$'
                                AND OWNER = 'SYS'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.3.1 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "AUD$"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized GRANTEE has privileges on AUD$
                                f.write('''<tr>
                                               <td>5.1.3.1 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "AUD$"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.3.1 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "AUD$"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.3.2 Ensure 'ALL' Is Revoked from Unauthorized 'GRANTEE'  on 'DBA_%' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, TABLE_NAME
                                FROM DBA_TAB_PRIVS
                                WHERE TABLE_NAME LIKE 'DBA\_%' ESCAPE '\\'
                                AND OWNER = 'SYS'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, TABLE_NAME,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE TABLE_NAME LIKE 'DBA\_%' ESCAPE '\\'
                                AND OWNER = 'SYS'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.3.2 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "DBA_%"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized GRANTEE has privileges on DBA_% objects
                                f.write('''<tr>
                                               <td>5.1.3.2 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "DBA_%"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.3.2 Ensure "ALL" Is Revoked from Unauthorized "GRANTEE" on "DBA_%"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.1.3.3 Ensure 'ALL' Is Revoked on 'Sensitive' Tables (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE, TABLE_NAME
                                FROM DBA_TAB_PRIVS
                                WHERE TABLE_NAME IN (
                                    'CDB_LOCAL_ADMINAUTH$', 'DEFAULT_PWD$', 'ENC$', 'HISTGRM$', 
                                    'HIST_HEAD$', 'LINK$', 'PDB_SYNC$', 'SCHEDULER$_CREDENTIAL', 
                                    'USER$', 'USER_HISTORY$', 'XS$VERIFIERS'
                                )
                                AND OWNER = 'SYS'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT TABLE_NAME, PRIVILEGE, GRANTEE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_TAB_PRIVS A
                                WHERE TABLE_NAME IN (
                                    'CDB_LOCAL_ADMINAUTH$', 'DEFAULT_PWD$', 'ENC$', 'HISTGRM$', 
                                    'HIST_HEAD$', 'LINK$', 'PDB_SYNC$', 'SCHEDULER$_CREDENTIAL', 
                                    'USER$', 'USER_HISTORY$', 'XS$VERIFIERS'
                                )
                                AND OWNER = 'SYS'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                                ORDER BY CON_ID, TABLE_NAME
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.1.3.3 Ensure "ALL" Is Revoked on "Sensitive" Tables</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized GRANTEE has privileges on sensitive tables
                                f.write('''<tr>
                                               <td>5.1.3.3 Ensure "ALL" Is Revoked on "Sensitive" Tables</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.1.3.3 Ensure "ALL" Is Revoked on "Sensitive" Tables</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 5.2 Excessive System Privileges

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                <strong>5.2 Excessive System Privileges</strong>  
                                    </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                              <th>Check</th>
                                              <th>Status</th>
                                           </tr>''')

                        # 5.2.1 Ensure "%ANY%" Is Revoked from Unauthorized "GRANTEE"
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE LIKE '%ANY%'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE LIKE '%ANY%'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.1 Ensure "%ANY%" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized GRANTEE has privileges containing '%ANY%'
                                f.write('''<tr>
                                               <td>5.2.1 Ensure "%ANY%" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.1 Ensure "%ANY%" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.2 Ensure 'DBA_SYS_PRIVS.%' Is Revoked from Unauthorized 'GRANTEE' with 'ADMIN_OPTION' Set to 'YES' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE ADMIN_OPTION = 'YES'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE ADMIN_OPTION = 'YES'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED = 'Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED = 'Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.2 Ensure "DBA_SYS_PRIVS.%" Is Revoked from Unauthorized "GRANTEE" with "ADMIN_OPTION" Set to "YES"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized GRANTEE has ADMIN_OPTION set to YES
                                f.write('''<tr>
                                               <td>5.2.2 Ensure "DBA_SYS_PRIVS.%" Is Revoked from Unauthorized "GRANTEE" with "ADMIN_OPTION" Set to "YES"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.2 Ensure "DBA_SYS_PRIVS.%" Is Revoked from Unauthorized "GRANTEE" with "ADMIN_OPTION" Set to "YES"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.3 Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'OUTLN' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'EXECUTE ANY PROCEDURE'
                                AND GRANTEE = 'OUTLN'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'EXECUTE ANY PROCEDURE'
                                AND GRANTEE = 'OUTLN'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.3 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "OUTLN"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if the OUTLN grantee has EXECUTE ANY PROCEDURE privilege
                                f.write('''<tr>
                                               <td>5.2.3 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "OUTLN"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.3 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "OUTLN"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.4 Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'DBSNMP' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'EXECUTE ANY PROCEDURE'
                                AND GRANTEE = 'DBSNMP'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'EXECUTE ANY PROCEDURE'
                                AND GRANTEE = 'DBSNMP'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.4 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "DBSNMP"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if the DBSNMP grantee has EXECUTE ANY PROCEDURE privilege
                                f.write('''<tr>
                                               <td>5.2.4 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "DBSNMP"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.4 Ensure "EXECUTE ANY PROCEDURE" Is Not Granted to "DBSNMP"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 5.2.5 Ensure 'SELECT ANY DICTIONARY' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'SELECT ANY DICTIONARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'SELECT ANY DICTIONARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for SELECT ANY DICTIONARY
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.5 Ensure "SELECT ANY DICTIONARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has SELECT ANY DICTIONARY privilege
                                f.write('''<tr>
                                               <td>5.2.5 Ensure "SELECT ANY DICTIONARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.5 Ensure "SELECT ANY DICTIONARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.6 Ensure 'SELECT ANY TABLE' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'SELECT ANY TABLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'SELECT ANY TABLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for SELECT ANY TABLE
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.6 Ensure "SELECT ANY TABLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has SELECT ANY TABLE privilege
                                f.write('''<tr>
                                               <td>5.2.6 Ensure "SELECT ANY TABLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.6 Ensure "SELECT ANY TABLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.7 Ensure 'AUDIT SYSTEM' Is Revoked from Unauthorized 'GRANTEE' (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'AUDIT SYSTEM'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'AUDIT SYSTEM'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for AUDIT SYSTEM
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.7 Ensure "AUDIT SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has AUDIT SYSTEM privilege
                                f.write('''<tr>
                                               <td>5.2.7 Ensure "AUDIT SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.7 Ensure "AUDIT SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.8 Ensure 'EXEMPT ACCESS POLICY' Is Revoked from Unauthorized 'GRANTEE' (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'EXEMPT ACCESS POLICY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'EXEMPT ACCESS POLICY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for EXEMPT ACCESS POLICY
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.8 Ensure "EXEMPT ACCESS POLICY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has EXEMPT ACCESS POLICY privilege
                                f.write('''<tr>
                                               <td>5.2.8 Ensure "EXEMPT ACCESS POLICY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.8 Ensure "EXEMPT ACCESS POLICY" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.9 Ensure 'BECOME USER' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'BECOME USER'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'BECOME USER'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for BECOME USER
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.9 Ensure "BECOME USER" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has BECOME USER privilege
                                f.write('''<tr>
                                               <td>5.2.9 Ensure "BECOME USER" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.9 Ensure "BECOME USER" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.10 Ensure 'CREATE PROCEDURE' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'CREATE PROCEDURE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'CREATE PROCEDURE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for CREATE PROCEDURE
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.10 Ensure "CREATE PROCEDURE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has CREATE PROCEDURE privilege
                                f.write('''<tr>
                                               <td>5.2.10 Ensure "CREATE PROCEDURE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.10 Ensure "CREATE PROCEDURE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.11 Ensure 'ALTER SYSTEM' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        # 5.2.11 Ensure 'ALTER SYSTEM' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'ALTER SYSTEM'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'ALTER SYSTEM'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for ALTER SYSTEM
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.11 Ensure "ALTER SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has ALTER SYSTEM privilege
                                f.write('''<tr>
                                               <td>5.2.11 Ensure "ALTER SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.11 Ensure "ALTER SYSTEM" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.12 Ensure 'CREATE ANY LIBRARY' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'CREATE ANY LIBRARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'CREATE ANY LIBRARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for CREATE ANY LIBRARY
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.12 Ensure "CREATE ANY LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has CREATE ANY LIBRARY privilege
                                f.write('''<tr>
                                               <td>5.2.12 Ensure "CREATE ANY LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.12 Ensure "CREATE ANY LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.13 Ensure 'CREATE LIBRARY' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'CREATE LIBRARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'CREATE LIBRARY'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for CREATE LIBRARY
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.13 Ensure "CREATE LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has CREATE LIBRARY privilege
                                f.write('''<tr>
                                               <td>5.2.13 Ensure "CREATE LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.13 Ensure "CREATE LIBRARY" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.14 Ensure 'GRANT ANY OBJECT PRIVILEGE' Is Revoked from Unauthorized 'GRANTEE'(Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'GRANT ANY OBJECT PRIVILEGE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'GRANT ANY OBJECT PRIVILEGE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for GRANT ANY OBJECT PRIVILEGE
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.14 Ensure "GRANT ANY OBJECT PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has GRANT ANY OBJECT PRIVILEGE
                                f.write('''<tr>
                                               <td>5.2.14 Ensure "GRANT ANY OBJECT PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.14 Ensure "GRANT ANY OBJECT PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.2.15 Ensure 'GRANT ANY ROLE' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'GRANT ANY ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'GRANT ANY ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for GRANT ANY ROLE
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.15 Ensure "GRANT ANY ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has GRANT ANY ROLE
                                f.write('''<tr>
                                               <td>5.2.15 Ensure "GRANT ANY ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.15 Ensure "GRANT ANY ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 5.2.16 Ensure 'GRANT ANY PRIVILEGE' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE
                                FROM DBA_SYS_PRIVS
                                WHERE PRIVILEGE = 'GRANT ANY PRIVILEGE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, PRIVILEGE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_SYS_PRIVS A
                                WHERE PRIVILEGE = 'GRANT ANY PRIVILEGE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for GRANT ANY PRIVILEGE
                            if not results:
                                f.write('''<tr>
                                               <td>5.2.16 Ensure "GRANT ANY PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has GRANT ANY PRIVILEGE
                                f.write('''<tr>
                                               <td>5.2.16 Ensure "GRANT ANY PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.2.16 Ensure "GRANT ANY PRIVILEGE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 5.3 Excessive Role Privileges

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                <strong>5.3 Excessive Role Privileges</strong>  
                                    </p>''')

                        # Start the table
                        f.write('''<table>
                                          <tr>
                                              <th>Check</th>
                                              <th>Status</th>
                                          </tr>''')
                        # 5.3.1 Ensure 'SELECT_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE' (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, GRANTED_ROLE
                                FROM DBA_ROLE_PRIVS
                                WHERE GRANTED_ROLE = 'SELECT_CATALOG_ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, GRANTED_ROLE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_ROLE_PRIVS A
                                WHERE GRANTED_ROLE = 'SELECT_CATALOG_ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for SELECT_CATALOG_ROLE
                            if not results:
                                f.write('''<tr>
                                               <td>5.3.1 Ensure "SELECT_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has SELECT_CATALOG_ROLE
                                f.write('''<tr>
                                               <td>5.3.1 Ensure "SELECT_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.3.1 Ensure "SELECT_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.3.2 Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE' (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT GRANTEE, GRANTED_ROLE
                                FROM DBA_ROLE_PRIVS
                                WHERE GRANTED_ROLE = 'EXECUTE_CATALOG_ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT GRANTEE, GRANTED_ROLE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS DATABASE
                                FROM CDB_ROLE_PRIVS A
                                WHERE GRANTED_ROLE = 'EXECUTE_CATALOG_ROLE'
                                AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE ORACLE_MAINTAINED='Y')
                                AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y')
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for EXECUTE_CATALOG_ROLE
                            if not results:
                                f.write('''<tr>
                                               <td>5.3.2 Ensure "EXECUTE_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has EXECUTE_CATALOG_ROLE
                                f.write('''<tr>
                                               <td>5.3.2 Ensure "EXECUTE_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.3.2 Ensure "EXECUTE_CATALOG_ROLE" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.3.3 Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE' (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE
                                FROM DBA_ROLE_PRIVS
                                WHERE GRANTED_ROLE = 'DBA' AND GRANTEE NOT IN ('SYS', 'SYSTEM')
                                UNION
                                SELECT 'PROXY', PROXY || '-' || CLIENT, 'DBA'
                                FROM DBA_PROXIES
                                WHERE CLIENT IN (SELECT GRANTEE
                                                 FROM DBA_ROLE_PRIVS
                                                 WHERE GRANTED_ROLE = 'DBA')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_ROLE_PRIVS A
                                WHERE GRANTED_ROLE = 'DBA'
                                AND GRANTEE NOT IN ('SYS', 'SYSTEM')
                                UNION
                                SELECT 'PROXY', PROXY || '-' || CLIENT, 'DBA',
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_PROXIES A
                                WHERE CLIENT IN (SELECT GRANTEE
                                                 FROM CDB_ROLE_PRIVS B
                                                 WHERE GRANTED_ROLE = 'DBA'
                                                 AND A.CON_ID = B.CON_ID)
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for DBA role
                            if not results:
                                f.write('''<tr>
                                               <td>5.3.3 Ensure "DBA" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has DBA role
                                f.write('''<tr>
                                               <td>5.3.3 Ensure "DBA" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.3.3 Ensure "DBA" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 5.3.4 Ensure AUDIT_ADMIN' Is Revoked from Unauthorized 'GRANTEE' (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE
                                FROM DBA_ROLE_PRIVS
                                WHERE GRANTED_ROLE = 'AUDIT_ADMIN' AND GRANTEE NOT IN ('SYS', 'SYSTEM')
                                UNION
                                SELECT 'PROXY', PROXY || '-' || CLIENT, 'AUDIT_ADMIN'
                                FROM DBA_PROXIES
                                WHERE CLIENT IN (SELECT GRANTEE
                                                 FROM DBA_ROLE_PRIVS
                                                 WHERE GRANTED_ROLE = 'AUDIT_ADMIN')
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE,
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_ROLE_PRIVS A
                                WHERE GRANTED_ROLE = 'AUDIT_ADMIN'
                                AND GRANTEE NOT IN ('SYS', 'SYSTEM')
                                UNION
                                SELECT 'PROXY', PROXY || '-' || CLIENT, 'AUDIT_ADMIN',
                                    DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                           1, (SELECT NAME FROM V$DATABASE),
                                           (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_PROXIES A
                                WHERE CLIENT IN (SELECT GRANTEE
                                                 FROM CDB_ROLE_PRIVS B
                                                 WHERE GRANTED_ROLE = 'AUDIT_ADMIN'
                                                 AND A.CON_ID = B.CON_ID)
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Check for compliance for AUDIT_ADMIN role
                            if not results:
                                f.write('''<tr>
                                               <td>5.3.4 Ensure "AUDIT_ADMIN" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                # Failed if any unauthorized grantee has AUDIT_ADMIN role
                                f.write('''<tr>
                                               <td>5.3.4 Ensure "AUDIT_ADMIN" Is Revoked from Unauthorized "GRANTEE"</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors (e.g., missing permissions)
                            f.write('''<tr>
                                           <td>5.3.4 Ensure "AUDIT_ADMIN" Is Revoked from Unauthorized "GRANTEE"</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 6 Audit/Logging Policies and Procedures

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                            <strong>6. Audit/Logging Policies and Procedures</strong>  
                                    </p>''')

                        # 6.1 Traditional Auditing

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                              <strong>6.1 Traditional Auditing</strong>  
                                   </p>''')

                        # Start the table
                        f.write('''<table>
                                            <tr>
                                                <th>Check</th>
                                                <th>Status</th>
                                            </tr>''')
                        # 6.1.1 Ensure the 'USER' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'USER'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'USER'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.1 Ensure the 'USER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.1 Ensure the 'USER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.1 Ensure the 'USER' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.2 Ensure the 'ROLE' Audit Option Is Enabled (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'ROLE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'ROLE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            for row in results:
                                audit_option, success, failure = row[0], row[1], row[2]

                                # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                    audit_compliance = True
                                else:
                                    audit_compliance = False
                                    break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.2 Ensure the 'ROLE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.2 Ensure the 'ROLE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.2 Ensure the 'ROLE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.3 Ensure the 'SYSTEM GRANT' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SYSTEM GRANT'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SYSTEM GRANT'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            for row in results:
                                audit_option, success, failure = row[0], row[1], row[2]

                                # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                    audit_compliance = True
                                else:
                                    audit_compliance = False
                                    break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.3 Ensure the 'SYSTEM GRANT' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.3 Ensure the 'SYSTEM GRANT' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.3 Ensure the 'SYSTEM GRANT' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.4 Ensure the 'PROFILE' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PROFILE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PROFILE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            for row in results:
                                audit_option, success, failure = row[0], row[1], row[2]

                                # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                    audit_compliance = True
                                else:
                                    audit_compliance = False
                                    break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.4 Ensure the 'PROFILE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.4 Ensure the 'PROFILE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.4 Ensure the 'PROFILE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.1.5 Ensure the 'DATABASE LINK' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DATABASE LINK'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DATABASE LINK'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            for row in results:
                                audit_option, success, failure = row[0], row[1], row[2]

                                # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                    audit_compliance = True
                                else:
                                    audit_compliance = False
                                    break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.5 Ensure the 'DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.5 Ensure the 'DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.5 Ensure the 'DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.6 Ensure the 'PUBLIC DATABASE LINK' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PUBLIC DATABASE LINK'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PUBLIC DATABASE LINK'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            for row in results:
                                audit_option, success, failure = row[0], row[1], row[2]

                                # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                    audit_compliance = True
                                else:
                                    audit_compliance = False
                                    break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.6 Ensure the 'PUBLIC DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.6 Ensure the 'PUBLIC DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.6 Ensure the 'PUBLIC DATABASE LINK' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.7 Ensure the 'PUBLIC SYNONYM' Audit Option Is Enabled (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PUBLIC SYNONYM'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PUBLIC SYNONYM'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.7 Ensure the 'PUBLIC SYNONYM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.7 Ensure the 'PUBLIC SYNONYM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.7 Ensure the 'PUBLIC SYNONYM' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.8 Ensure the 'SYNONYM' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SYNONYM'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SYNONYM'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.8 Ensure the 'SYNONYM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.8 Ensure the 'SYNONYM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.8 Ensure the 'SYNONYM' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.1.9 Ensure the 'DIRECTORY' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DIRECTORY'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DIRECTORY'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.9 Ensure the 'DIRECTORY' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.9 Ensure the 'DIRECTORY' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.9 Ensure the 'DIRECTORY' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.10 Ensure the 'SELECT ANY DICTIONARY' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SELECT ANY DICTIONARY'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'SELECT ANY DICTIONARY'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.10 Ensure the 'SELECT ANY DICTIONARY' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.10 Ensure the 'SELECT ANY DICTIONARY' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.10 Ensure the 'SELECT ANY DICTIONARY' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.11 Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'GRANT ANY OBJECT PRIVILEGE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'GRANT ANY OBJECT PRIVILEGE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.11 Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.11 Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.11 Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.1.12 Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'GRANT ANY PRIVILEGE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'GRANT ANY PRIVILEGE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.12 Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.12 Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.12 Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.1.13 Ensure the 'DROP ANY PROCEDURE' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DROP ANY PROCEDURE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                       DECODE(A.CON_ID, 0, (SELECT NAME FROM V$DATABASE),
                                              1, (SELECT NAME FROM V$DATABASE),
                                              (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) AS CON
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'DROP ANY PROCEDURE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                for row in results:
                                    audit_option, success, failure = row[0], row[1], row[2]

                                    # Check if the audit option is enabled by verifying 'SUCCESS' and 'FAILURE' fields
                                    if success == 'BY ACCESS' and failure == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.13 Ensure the 'DROP ANY PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.13 Ensure the 'DROP ANY PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.13 Ensure the 'DROP ANY PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.14 Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT *
                                FROM DBA_OBJ_AUDIT_OPTS
                                WHERE OBJECT_NAME = 'AUD$'
                                AND ALT = 'A/A'
                                AND AUD = 'A/A'
                                AND COM = 'A/A'
                                AND DEL = 'A/A'
                                AND GRA = 'A/A'
                                AND IND = 'A/A'
                                AND INS = 'A/A'
                                AND LOC = 'A/A'
                                AND REN = 'A/A'
                                AND SEL = 'A/A'
                                AND UPD = 'A/A'
                                AND FBK = 'A/A'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT *
                                FROM CDB_OBJ_AUDIT_OPTS
                                WHERE OBJECT_NAME = 'AUD$'
                                AND ALT = 'A/A'
                                AND AUD = 'A/A'
                                AND COM = 'A/A'
                                AND DEL = 'A/A'
                                AND GRA = 'A/A'
                                AND IND = 'A/A'
                                AND INS = 'A/A'
                                AND LOC = 'A/A'
                                AND REN = 'A/A'
                                AND SEL = 'A/A'
                                AND UPD = 'A/A'
                                AND FBK = 'A/A'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                # Check if all required audit options are set to 'A/A'
                                for row in results:
                                    if all(field == 'A/A' for field in row[1:]):  # Skip OBJECT_NAME
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.14 Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.14 Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.14 Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.15 Ensure the 'PROCEDURE' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PROCEDURE'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                DECODE (A.CON_ID,
                                    0, (SELECT NAME FROM V$DATABASE),
                                    1, (SELECT NAME FROM V$DATABASE),
                                    (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'PROCEDURE'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                # Check if the required audit option is set correctly
                                for row in results:
                                    if row[0] == 'PROCEDURE' and row[1] == 'BY ACCESS' and row[2] == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.15 Ensure the 'PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.15 Ensure the 'PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.15 Ensure the 'PROCEDURE' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.16 Ensure the 'ALTER SYSTEM' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'ALTER SYSTEM'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                DECODE (A.CON_ID,
                                    0, (SELECT NAME FROM V$DATABASE),
                                    1, (SELECT NAME FROM V$DATABASE),
                                    (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'ALTER SYSTEM'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                # Check if the required audit option is set correctly
                                for row in results:
                                    if row[0] == 'ALTER SYSTEM' and row[1] == 'BY ACCESS' and row[2] == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.16 Ensure the 'ALTER SYSTEM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.16 Ensure the 'ALTER SYSTEM' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.16 Ensure the 'ALTER SYSTEM' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.1.17 Ensure the 'TRIGGER' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'TRIGGER'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                DECODE (A.CON_ID,
                                    0, (SELECT NAME FROM V$DATABASE),
                                    1, (SELECT NAME FROM V$DATABASE),
                                    (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'TRIGGER'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                # Check if the required audit option is set correctly
                                for row in results:
                                    if row[0] == 'TRIGGER' and row[1] == 'BY ACCESS' and row[2] == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.17 Ensure the 'TRIGGER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.17 Ensure the 'TRIGGER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.17 Ensure the 'TRIGGER' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.1.18 Ensure the 'CREATE SESSION' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Non multi-tenant query (non-CDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE
                                FROM DBA_STMT_AUDIT_OPTS
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'CREATE SESSION'
                            """)

                            # Fetch the results for non-multi-tenant query
                            results_non_multi = cursor.fetchall()

                            # Multi-tenant query (CDB/PDB)
                            cursor.execute("""
                                SELECT AUDIT_OPTION, SUCCESS, FAILURE,
                                DECODE (A.CON_ID,
                                    0, (SELECT NAME FROM V$DATABASE),
                                    1, (SELECT NAME FROM V$DATABASE),
                                    (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
                                FROM CDB_STMT_AUDIT_OPTS A
                                WHERE USER_NAME IS NULL
                                AND PROXY_NAME IS NULL
                                AND SUCCESS = 'BY ACCESS'
                                AND FAILURE = 'BY ACCESS'
                                AND AUDIT_OPTION = 'CREATE SESSION'
                            """)

                            # Fetch the results for multi-tenant query
                            results_multi = cursor.fetchall()

                            # Combine results from both queries
                            results = results_non_multi + results_multi

                            # Initialize a variable to track compliance
                            audit_compliance = False

                            # Check for compliance in both queries
                            if not results:
                                # No results indicate a finding
                                audit_compliance = False
                            else:
                                # Check if the required audit option is set correctly
                                for row in results:
                                    if row[0] == 'CREATE SESSION' and row[1] == 'BY ACCESS' and row[2] == 'BY ACCESS':
                                        audit_compliance = True
                                    else:
                                        audit_compliance = False
                                        break  # Exit loop early if any entry is not compliant

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.1.18 Ensure the 'CREATE SESSION' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.1.18 Ensure the 'CREATE SESSION' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.1.18 Ensure the 'CREATE SESSION' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # 6.2 Unified Auditing

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                <strong>6.2 Unified Auditing</strong>  
                                   </p>''')

                        # Start the table
                        f.write('''<table>
                                           <tr>
                                                <th>Check</th>
                                                <th>Status</th>
                                           </tr>''')

                        # 6.2.1 Ensure the 'CREATE USER' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE USER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('CREATE USER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE USER' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance isn't met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.2.1 Ensure the 'CREATE USER' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.2.1 Ensure the 'CREATE USER' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.1 Ensure the 'CREATE USER' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.2 Ensure the 'ALTER USER' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER USER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER USER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER USER' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.2.2 Ensure the 'ALTER USER' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.2.2 Ensure the 'ALTER USER' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.2 Ensure the 'ALTER USER' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.3 Ensure the 'DROP USER' Audit Option Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP USER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('DROP USER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP USER' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.2.3 Ensure the 'DROP USER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.2.3 Ensure the 'DROP USER' Audit Option Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.3 Ensure the 'DROP USER' Audit Option Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.4 Ensure the 'CREATE ROLE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE ROLE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('CREATE ROLE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE ROLE' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.4 Ensure the 'CREATE ROLE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.4 Ensure the 'CREATE ROLE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.4 Ensure the 'CREATE ROLE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.5 Ensure the 'ALTER ROLE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER ROLE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER ROLE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER ROLE' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.5 Ensure the 'ALTER ROLE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                          </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                                <td>6.2.5 Ensure the 'ALTER ROLE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.5 Ensure the 'ALTER ROLE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.6 Ensure the 'DROP ROLE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP ROLE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('DROP ROLE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP ROLE' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.6 Ensure the 'DROP ROLE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.2.6 Ensure the 'DROP ROLE' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.6 Ensure the 'DROP ROLE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.7 Ensure the 'GRANT' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'GRANT' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('GRANT' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('GRANT' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.2.7 Ensure the 'GRANT' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                               <td>6.2.7 Ensure the 'GRANT' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.7 Ensure the 'GRANT' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.2.8 Ensure the 'REVOKE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'REVOKE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('REVOKE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('REVOKE' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                               <td>6.2.8 Ensure the 'REVOKE' Action Audit Is Enabled (Automated)</td>
                                               <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                                <td>6.2.8 Ensure the 'REVOKE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.8 Ensure the 'REVOKE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.9 Ensure the 'CREATE PROFILE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE PROFILE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('CREATE PROFILE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE PROFILE')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.9 Ensure the 'CREATE PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                          </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.9 Ensure the 'CREATE PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.9 Ensure the 'CREATE PROFILE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.10 Ensure the 'ALTER PROFILE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER PROFILE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER PROFILE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER PROFILE')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.10 Ensure the 'ALTER PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.10 Ensure the 'ALTER PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.10 Ensure the 'ALTER PROFILE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.11 Ensure the 'DROP PROFILE' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP PROFILE' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('DROP PROFILE' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP PROFILE')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.11 Ensure the 'DROP PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                            </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.11 Ensure the 'DROP PROFILE' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                            </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.11 Ensure the 'DROP PROFILE' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.12 Ensure the 'CREATE DATABASE LINK' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE DATABASE LINK' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('CREATE DATABASE LINK' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE DATABASE LINK')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                 <td>6.2.12 Ensure the 'CREATE DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                 <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.12 Ensure the 'CREATE DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                          </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.12 Ensure the 'CREATE DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.13 Ensure the 'ALTER DATABASE LINK' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER DATABASE LINK' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER DATABASE LINK' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER DATABASE LINK')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                 <td>6.2.13 Ensure the 'ALTER DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                 <td class="status-failed">Failed</td>
                                          </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                               <td>6.2.13 Ensure the 'ALTER DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.13 Ensure the 'ALTER DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.14 Ensure the 'DROP DATABASE LINK' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP DATABASE LINK' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('DROP DATABASE LINK' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP DATABASE LINK')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.14 Ensure the 'DROP DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                          </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.14 Ensure the 'DROP DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.14 Ensure the 'DROP DATABASE LINK' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.15 Ensure the 'CREATE SYNONYM' Action Audit Is Enabled (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE SYNONYM' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('CREATE SYNONYM' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE SYNONYM')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.15 Ensure the 'CREATE SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                          </tr>''')
                                Failed += 1
                            else:
                                f.write('''<tr>
                                                <td>6.2.15 Ensure the 'CREATE SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.15 Ensure the 'CREATE SYNONYM' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.16 Ensure the 'ALTER SYNONYM' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER SYNONYM' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER SYNONYM' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER SYNONYM' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.16 Ensure the 'ALTER SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.16 Ensure the 'ALTER SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.16 Ensure the 'ALTER SYNONYM' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.17 Ensure the 'DROP SYNONYM' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP SYNONYM' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('DROP SYNONYM' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP SYNONYM' )
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.17 Ensure the 'DROP SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.17 Ensure the 'DROP SYNONYM' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.17 Ensure the 'DROP SYNONYM' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        # 6.2.18 Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'SELECT ANY DICTIONARY' privilege audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('SELECT ANY DICTIONARY') )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('SELECT ANY DICTIONARY')
                                    AND AUD.AUDIT_OPTION_TYPE = 'SYSTEM PRIVILEGE'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.18 Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.18 Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.18 Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.19 Ensure the 'AUDSYS.AUD$UNIFIED' Access Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'AUDSYS.AUD$UNIFIED' access audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('AUD$UNIFIED') )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT OBJECT_NAME
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALL')
                                    AND AUD.AUDIT_OPTION_TYPE = 'OBJECT ACTION'
                                    AND AUD.OBJECT_SCHEMA = 'AUDSYS'
                                    AND AUD.OBJECT_NAME = 'AUD$UNIFIED'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.OBJECT_NAME
                                WHERE E.OBJECT_NAME IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.19 Ensure the 'AUDSYS.AUD$UNIFIED' Access Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.19 Ensure the 'AUDSYS.AUD$UNIFIED' Access Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.19 Ensure the 'AUDSYS.AUD$UNIFIED' Access Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.20 Ensure the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY(
                                        'CREATE PROCEDURE', 'CREATE FUNCTION', 'CREATE PACKAGE', 'CREATE PACKAGE BODY'
                                    ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE PROCEDURE', 'CREATE FUNCTION', 'CREATE PACKAGE', 'CREATE PACKAGE BODY')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.20 Ensure the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.20 Ensure the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.20 Ensure the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.21 Ensure the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY(
                                        'ALTER PROCEDURE', 'ALTER FUNCTION', 'ALTER PACKAGE', 'ALTER PACKAGE BODY'
                                    ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER PROCEDURE', 'ALTER FUNCTION', 'ALTER PACKAGE', 'ALTER PACKAGE BODY')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.21 Ensure the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.21 Ensure the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.21 Ensure the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY(
                                        'DROP PROCEDURE', 'DROP FUNCTION', 'DROP PACKAGE', 'DROP PACKAGE BODY'
                                    ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP PROCEDURE', 'DROP FUNCTION', 'DROP PACKAGE', 'DROP PACKAGE BODY')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.22 Ensure the 'DROP PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.22 Ensure the 'DROP PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.22 Ensure the 'DROP PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER SYSTEM' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'ALTER SYSTEM' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER SYSTEM')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.23 Ensure the 'ALTER SYSTEM' Action Audit is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.23 Ensure the 'ALTER SYSTEM' Action Audit is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.23 Ensure the 'ALTER SYSTEM' Action Audit is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.24 Ensure the 'CREATE TRIGGER' Action Audit Is Enabled (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'CREATE TRIGGER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'CREATE TRIGGER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('CREATE TRIGGER')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.24 Ensure the 'CREATE TRIGGER' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.24 Ensure the 'CREATE TRIGGER' Action Audit Is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.24 Ensure the 'CREATE TRIGGER' Action Audit Is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.25 Ensure the 'ALTER TRIGGER' Action Audit IS Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'ALTER TRIGGER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'ALTER TRIGGER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('ALTER TRIGGER')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.25 Ensure the 'ALTER TRIGGER' Action Audit is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.25 Ensure the 'ALTER TRIGGER' Action Audit is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.25 Ensure the 'ALTER TRIGGER' Action Audit is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.26 Ensure the 'DROP TRIGGER' Action Audit Is Enabled (Automated)

                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'DROP TRIGGER' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'DROP TRIGGER' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('DROP TRIGGER')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.26 Ensure the 'DROP TRIGGER' Action Audit is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.26 Ensure the 'DROP TRIGGER' Action Audit is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.26 Ensure the 'DROP TRIGGER' Action Audit is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # 6.2.27 Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled (Automated)
                        try:
                            # Create a cursor for the database connection
                            cursor = connection.cursor()

                            # Execute the SQL query to check for the 'LOGON' and 'LOGOFF' action audit
                            cursor.execute("""
                                WITH
                                CIS_AUDIT(AUDIT_OPTION) AS
                                (
                                    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'LOGON', 'LOGOFF' ) )
                                ),
                                AUDIT_ENABLED AS
                                (
                                    SELECT DISTINCT AUDIT_OPTION
                                    FROM AUDIT_UNIFIED_POLICIES AUD
                                    WHERE AUD.AUDIT_OPTION IN ('LOGON', 'LOGOFF')
                                    AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
                                    AND EXISTS (SELECT *
                                                FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
                                                WHERE ENABLED.SUCCESS = 'YES'
                                                AND ENABLED.FAILURE = 'YES'
                                                AND ENABLED.ENABLED_OPTION = 'BY USER'
                                                AND ENABLED.ENTITY_NAME = 'ALL USERS'
                                                AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
                                )
                                SELECT C.AUDIT_OPTION
                                FROM CIS_AUDIT C
                                LEFT JOIN AUDIT_ENABLED E
                                ON C.AUDIT_OPTION = E.AUDIT_OPTION
                                WHERE E.AUDIT_OPTION IS NULL
                            """)

                            # Fetch the results
                            results = cursor.fetchall()

                            # Initialize a variable to track compliance
                            audit_compliance = len(results) > 0  # If results are found, compliance is not met

                            # Write the result to the report based on audit_compliance
                            if audit_compliance:
                                f.write('''<tr>
                                                <td>6.2.27 Ensure the 'LOGON' and 'LOGOFF' Actions Audit is Enabled (Automated)</td>
                                                <td class="status-failed">Failed</td>
                                           </tr>''')
                                Failed += 1

                            else:
                                f.write('''<tr>
                                                <td>6.2.27 Ensure the 'LOGON' and 'LOGOFF' Actions Audit is Enabled (Automated)</td>
                                                <td class="status-passed">Passed</td>
                                           </tr>''')
                                Passed += 1

                        except cx_Oracle.DatabaseError as e:
                            # Handle any database errors
                            f.write('''<tr>
                                           <td>6.2.27 Ensure the 'LOGON' and 'LOGOFF' Actions Audit is Enabled (Automated)</td>
                                           <td class="status-nopermission">NoPermission</td>
                                       </tr>''')
                            NoPermission += 1

                        # Close the first table
                        f.write("</table>")

                        # Open the table after all rows are written
                        f.write('''<table class="summary-table" style="width: 100%; margin-top: 20px; border-collapse: collapse;">
                                            <tr>
                                               <th>Total Passed</th>
                                                <th>Total Failed</th>
                                                <th>Total Manual</th>
                                                <th>No Permission</th>
                                            </tr>
                                            <tr>
                                                <td class="status-passed" style="text-align: center;">{}</td>
                                                <td class="status-failed" style="text-align: center;">{}</td>
                                                <td class="status-manual" style="text-align: center;">{}</td>
                                                <td class="status-nopermission" style="text-align: center;">{}</td>
                                            </tr>
                                   </table>
                                   <footer style="text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0;">
                                            <p> 2024 All Rights Reserved to Secure Auditix tool</p>
                                            <p>Coded and UI Designed by <strong>Mandavalli Ganesh<strong></p>
                                   </footer>
                                   </body>
                                   </html>'''.format(Passed, Failed, Manual, NoPermission, Passed,
                                                     Failed, Manual,
                                                     NoPermission))
                        # Return the generated HTML file as a download
                        with open(file_path, 'r') as file:
                            response = HttpResponse(file.read(), content_type='text/html')
                            response['Content-Disposition'] = f'attachment; filename={file_name}'
                            return response

                    elif selected_standard == "DISA_STIG":
                        # Connect to Oracle database
                        connection = cx_Oracle.connect(username, password, dsn)
                        cursor = connection.cursor()

                        # Get the current date and time for the report
                        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        # Define the file path for the audit report in Django's media directory
                        file_name = "Oracle_Audit_Report.htm"
                        file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                        # Ensure the media directory exists
                        os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

                        with open(file_path, "w") as f:
                            f.write(f"""<html lang="en">
                                          <head>
                                             <meta charset="UTF-8">
                                             <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                             <title>Audit Report</title>
                                             <style>
                                                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                                .header {{ text-align: right; font-size: 14px; margin-bottom: 10px; }}
                                                .info-box {{ background-color: #f2f2f2; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }}
                                                 h2 {{ color: #00008B; text-align: center; margin-top: 20px; }}
                                                 h3 {{ color: #00008B; text-align: left; margin-top: 20px; }}
                                                 table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                                                 table, th, td {{ border: 1px solid #ddd; }}
                                                 th, td {{ padding: 12px; text-align: left; }}
                                                 th {{ background-color: #00008B; color: white; }}
                                                 tr:nth-child(even) {{ background-color: #f2f2f2; }}
                                                 .status-passed {{ color: green; }}
                                                 .status-failed {{ color: red; }}
                                                 .status-manual {{ color: black; }}
                                                 .status-nopermission {{ color: yellow; }}
                                                 .footer {{ text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0; }}
                                                 .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 10px; text-align: center; font-weight: bold; }}
                                                 .summary-table th {{ background-color: #00008B; color: white; }}
                                             </style>
                                          </head>
                                          <body>
                                               <div class="header"><strong>Audit Date: </strong>{current_datetime}</div>
                                               <h2>Database Audit Results</h2>
                                               <h3>Version Information:</h3>
                            """)

                            # Execute the query to fetch database version
                            cursor.execute("SELECT banner AS version FROM v$version")
                            version_info = cursor.fetchall()

                            # Loop through the result and write it into the HTML file
                            for row in version_info:
                                f.write(f'''<div class="info-box">
                                                <p><strong>{row[0]}</strong><br> </p> 
                                          </div>''')

                            # Add a horizontal line for separation
                            f.write("<hr style='border: 1px solid #00008B; margin: 20px 0;'>\n")

                            # Write additional messages
                            f.write(
                                "<p style='font-weight: bold; color: #00008B;'>Database Auditing - DISA STIG is coming soon...</p>\n")
                            f.write("<p>Currently under maintenance, Update is coming in next release.</p>\n")
                            f.write("<p>Thank you - Please Visit again.</p>\n")

                            # Add footer
                            f.write("""<footer style="text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0;">
                                          <p> 2024 All Rights Reserved to Secure Auditix tool</p>
                                          <p>Coded and UI Designed by <strong>Mandavalli Ganesh</strong></p>
                                       </footer>
                                       </body>
                                       </html>""")

                        # Return the HTML file as a downloadable attachment
                        with open(file_path, 'r') as file:
                            response = HttpResponse(file.read(), content_type='text/html')
                            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                            return response

            elif db_type == "MS SQL":
                # Connect to MS SQL Server
                connection_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}"
                connection = pyodbc.connect(connection_str)
                # Establish a connection to the SQL Server
                conn = pyodbc.connect(
                    f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password};'
                )

                cursor = conn.cursor()

                # Define download path
                # Define file path inside Django's media directory
                file_name = "MS SQL_Results.htm"
                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                # Ensure MEDIA_ROOT exists
                os.makedirs(settings.MEDIA_ROOT, exist_ok=True)


                # Get the current date and time
                current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Write HTML content to the file
                with open(file_path, "w") as f:
                    f.write(f"""<html lang="en">
                                                            <head>
                                                               <meta charset="UTF-8">
                                                               <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                                               <title>Audit Report</title>
                                                                 <style>
                                                                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                                                    .header {{ text-align: right; font-size: 14px; margin-bottom: 10px; }}
                                                                    .info-box {{ background-color: #f2f2f2; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }}
                                                                     h2 {{ color: #00008B; text-align: center; margin-top: 20px; }}
                                                                     h3 {{ color: #00008B; text-align: left; margin-top: 20px; }}
                                                                     table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                                                                     table, th, td {{ border: 1px solid #ddd; }}
                                                                     th, td {{ padding: 12px; text-align: left; }}
                                                                     th {{ background-color: #00008B; color: white; }}
                                                                     tr:nth-child(even) {{ background-color: #f2f2f2; }}
                                                                     .status-passed {{ color: green; }}
                                                                     .status-failed {{ color: red; }}
                                                                     .status-manual {{ color: black; }}
                                                                     .status-nopermission {{ color: yellow; }}
                                                                     .footer {{ text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0; }}
                                                                     .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 10px; text-align: center; font-weight: bold; }}
                                                                     .summary-table th {{ background-color: #00008B; color: white; }}
                                                                 </style>
                                                            </head>
                                                                <body>
                                                                    <div class="header"><strong>Audit Date: </strong>{current_datetime}</div>
                                                     """)

                    if selected_standard == "CIS":
                        # Run CIS-related queries
                        # Get all databases names and save them in an array
                        cursor.execute("select name FROM sys.databases;")
                        row = cursor.fetchone()
                        dbNames = []

                        while row:
                            dbNames.append(row[0])
                            row = cursor.fetchone()

                        # Get user databases names and save them in an array
                        cursor.execute("""SELECT name FROM sys.databases
                                                  WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb', 'Resource')""")

                        row = cursor.fetchone()
                        userdbNames = []

                        while row:
                            userdbNames.append(row[0])
                            row = cursor.fetchone()

                        # Start writing the results in it

                        cursor.execute("""select @@version;""")

                        row = cursor.fetchone()

                        version = []

                        while row:
                            version.append(row[0])
                            row = cursor.fetchone()

                        string = ""

                        # Starting a for loop to traverse through the list elements
                        for element in version:
                            string = string + " " + element  # Using " " as a separator for the elements of the string. However, it will add an extra space at the beginning of the string

                        # Write to the HTML file
                        f.write('''<div class="info-box">
                                                      <p><strong>{}</strong><br> 
                                                      </p> 
                                                  </div>'''.format(
                            string.strip()))  # Use .strip() to remove the leading space

                        # Count the pass, fail & Manual items.
                        Passed = 0
                        Failed = 0
                        Manual = 0
                        NoPermission = 0

                        f.write(f"<h2>Database Audit Report - CIS_Microsoft_SQL_Server_2022_Benchmark_v1.1.0 </h2>")
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                      <strong> 1. Installation, Updates and Patches </strong>  
                                                  </p>''')

                        # Start the table
                        f.write('''<table>
                                                               <tr>
                                                                <th>Check</th>
                                                                <th>Status</th>
                                                               </tr>''')

                        # 1.1 Ensure Latest SQL Server Cumulative and Security Updates are Installed

                        if "2022" in string and "16.0" in string:
                            f.write('''<tr>
                                                                     <td>1.1 Ensure Latest SQL Server Cumulative and Security Updates are Installed (Manual) </td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1
                        else:
                            f.write('''<tr>
                                                                  <td>1.1 Ensure Latest SQL Server Cumulative and Security Updates are Installed (Manual)</td>
                                                                  <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 1.2 Ensure Single-Function Member Servers are Used (Manual)
                        f.write('''<tr>
                                                                 <td>1.2  Ensure Single-Function Member Servers are Used (Manual)</td>
                                                                 <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # Close the first table
                        f.write("</table>")

                        ########################################## 2.Surface Area Reduction #####################################################
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                     <strong>2. Surface Area Reduction</strong>
                                                                  </p>''')

                        # Start the table
                        f.write('''<table>
                                                               <tr>
                                                                   <th>Check</th>
                                                                   <th>Status</th>
                                                               </tr>''')

                        # 2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
                        cursor.execute("""SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as
                                                  int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'Ad Hoc Distributed Queries';""")
                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                      <td>2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                     <td>2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0' (Scored)
                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'clr strict security';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0'(Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1
                        elif row[1] == 1 and row[2] == 1:
                            f.write('''<tr>
                                                                     <td>2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0'(Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1
                        else:
                            f.write('''<tr>
                                                                     <td>2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0'(Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored)
                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'cross db ownership chaining';""")
                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                     <td>2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;
                        else:
                            f.write('''<tr>
                                                                     <td>2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Automated)

                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'Database Mail XPs';""")

                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                     <td>2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                     <td>2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 2.5 Ensure 'Ole Automation Procedures' Server Configuration option is set to '0' (Automated)

                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'Ole Automation Procedures';""")

                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                      <td>2.5 Ensure 'Ole Automation Procedures' Server Configuration option is set to '0' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.5 Ensure 'Ole Automation Procedures' Server Configuration option is set to '0' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Automated)

                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'remote access';""")

                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                      <td>2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Automated)

                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'remote admin connections'
                                                  AND SERVERPROPERTY('IsClustered') = 0;""")

                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                     <td>2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                  </tr>''')
                            Failed += 1;

                        # 2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Automated)

                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'scan for startup procs';""")

                        row = cursor.fetchone()

                        if row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                     <td>2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;
                        else:
                            f.write('''<tr>
                                                                      <td>2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Automated)

                        cursor.execute("""SELECT name
                                                  FROM sys.databases
                                                  WHERE is_trustworthy_on = 1
                                                  AND name != 'msdb';""")

                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>2.9 Ensure 'Trustworthy' Database Property is set to 'Off'(Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.9 Ensure 'Trustworthy' Database Property is set to 'Off'(Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Manual)'
                        f.write('''<tr>
                                                                 <td>2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Manual)'</td>
                                                                 <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 2.11 Ensure SQL Server is configured to use non-standard ports (Automated)

                        cursor.execute("""DECLARE @value nvarchar(256);
                                                  EXECUTE master.dbo.xp_instance_regread
                                                  N'HKEY_LOCAL_MACHINE',
                                                  N'SOFTWARE\Microsoft\Microsoft SQL
                                                  Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',
                                                  N'TcpPort',
                                                  @value OUTPUT,
                                                  N'no_output';
                                                  SELECT @value AS TCP_Port WHERE @value = '1433';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>2.11 Ensure 'Trustworthy' Database Property is set to 'Off'(Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                  </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.11 Ensure 'Trustworthy' Database Property is set to 'Off'(Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Automated)

                        cursor.execute("""DECLARE @getValue INT;
                                                  EXEC master.sys.xp_instance_regread
                                                  @rootkey = N'HKEY_LOCAL_MACHINE',
                                                  @key = N'SOFTWARE\Microsoft\Microsoft SQL
                                                  Server\MSSQLServer\SuperSocketNetLib',
                                                  @value_name = N'HideInstance',
                                                  @value = @getValue OUTPUT;
                                                  SELECT @getValue;""")

                        try:
                            row = cursor.fetchone()

                            if row[0] == 1:
                                f.write('''<tr>
                                                                         <td>2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Automated)</td>
                                                                         <td class="status-passed">Passed</td>
                                                                     </tr>''')
                                Passed += 1;

                            else:
                                f.write('''<tr>
                                                                         <td>2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Automated)</td>
                                                                         <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1;

                        except pyodbc.ProgrammingError:
                            f.write('''<tr>
                                                                     <td>2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.13 Ensure the 'sa' Login Account is set to 'Disabled' (Automated)
                        cursor.execute("""SELECT name, is_disabled
                                                  FROM sys.server_principals
                                                  WHERE sid = 0x01;""")
                        row = cursor.fetchone()

                        if row[1] == 0:
                            f.write('''<tr>
                                                                      <td>2.13 Ensure the 'sa' Login Account is set to 'Disabled' (Automated)</td>
                                                                       <td class="status-failed">Failed</td>
                                                                </tr>''')
                            Failed += 1;
                        else:
                            f.write('''<tr>
                                                                      <td>2.13 Ensure the 'sa' Login Account is set to 'Disabled' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        # 2.14 Ensure 'sa' Login Account has been renamed (Scored)
                        cursor.execute("""SELECT name
                                                  FROM sys.server_principals
                                                  WHERE sid = 0x01;""")
                        row = cursor.fetchone()

                        if row[0] == "sa":
                            f.write('''<tr>
                                                                      <td>2.14 Ensure 'sa' Login Account has been renamed (Scored)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        else:
                            f.write('''<tr>
                                                                     <td>2.14 Ensure 'sa' Login Account has been renamed (Scored)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        # 2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Automated)
                        cursor.execute("""SELECT name, containment, containment_desc, is_auto_close_on
                                                  FROM sys.databases
                                                  WHERE containment <> 0 and is_auto_close_on = 1;""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;
                        else:
                            f.write('''<tr>
                                                                      <td>2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.16 Ensure no login exists with the name 'sa' (Automated)
                        cursor.execute("""SELECT principal_id, name
                                                  FROM sys.server_principals
                                                  WHERE name = 'sa';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>2.16 Ensure no login exists with the name 'sa' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>2.16 Ensure no login exists with the name 'sa' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 2.17 Ensure 'clr strict security' Server Configuration Option is set to '1' (Automated)
                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'clr strict security';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>2.17 Ensure 'clr strict security' Server Configuration Option is set to '1' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                </tr>''')
                            Failed += 1;

                        elif row[1] == 0 and row[2] == 0:
                            f.write('''<tr>
                                                                      <td>2.17 Ensure 'clr strict security' Server Configuration Option is set to '1' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                </tr>''')
                            Failed += 1;

                        else:
                            f.write('''<tr>
                                                                     <td>2.17 Ensure 'clr strict security' Server Configuration Option is set to '1' (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        # Close the first table
                        f.write("</table>")

                        ########################################### 3.Authentication and Authorization #####################################################

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                 <strong>3.Authentication and Authorization</strong> </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                        <th>Check</th>
                                                                        <th>Status</th>
                                                                    </tr>''')

                        # 3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Automated)
                        cursor.execute(
                            "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') as int) as [login_mode];")
                        row = cursor.fetchone()

                        if row[0] == 1:
                            f.write('''<tr>
                                                                      <td>3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;

                        else:
                            f.write('''<tr>
                                                                      <td>3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases (Automated)
                        i = 0
                        while i < len(dbNames):

                            if dbNames[i] == "master" or dbNames[i] == "tempdb" or dbNames[i] == "msdb":
                                i += 1
                                continue

                            cursor.execute("USE " + dbNames[i])
                            cursor.execute("""SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User,
                                                      [permission_name], [state_desc]
                                                      FROM sys.database_permissions
                                                      WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
                                                      AND [state_desc] LIKE 'GRANT%'
                                                      AND [permission_name] = 'CONNECT'
                                                      AND DB_NAME() NOT IN ('master','tempdb','msdb');""")

                            try:
                                row = cursor.fetchone()
                                if cursor.rowcount != 0:
                                    f.write('''<tr>
                                                                             <td>3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases (Automated)</td>
                                                                             <td class="status-failed">Failed</td>
                                                                         </tr>''')
                                    Failed += 1;

                                    break
                                else:
                                    if i == len(dbNames) - 1:
                                        f.write('''<tr>
                                                                                  <td>3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases (Automated)</td>
                                                                                  <td class="status-passed">Passed</td>
                                                                              </tr>''')
                                        Passed += 1;

                                i += 1
                            except pyodbc.ProgrammingError:
                                f.write('''<tr>
                                                                         <td>3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases (Automated)</td>
                                                                         <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                NoPermission += 1

                        # 3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)
                        i = 0
                        while i < len(dbNames):

                            cursor.execute("USE " + dbNames[i])
                            cursor.execute("""SELECT dp.type_desc, dp.sid, dp.name as orphan_user_name,
                                                      dp.authentication_type_desc FROM sys.database_principals AS dp LEFT JOIN
                                                      sys.server_principals as sp ON dp.sid=sp.sid WHERE sp.sid IS NULL AND
                                                      dp.authentication_type_desc = 'INSTANCE'""")

                            row = cursor.fetchone()
                            if cursor.rowcount != 0:
                                f.write('''<tr>
                                                                          <td>3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1;

                                break
                            else:
                                if i == len(dbNames) - 1:
                                    f.write('''<tr>
                                                                              <td>3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                         </tr>''')
                                    Passed += 1;

                            i += 1

                        # 3.4 Ensure SQL Authentication is not used in contained databases (Automated)

                        cursor.execute("USE master")
                        cursor.execute("""SELECT name AS DBUser
                                                  FROM sys.database_principals
                                                  WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
                                                  AND type IN ('U','S','G')
                                                  AND authentication_type = 2;""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>3.4 Ensure SQL Authentication is not used in contained databases (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1;
                        else:
                            f.write('''<tr>
                                                                     <td>3.4 Ensure SQL Authentication is not used in contained databases (Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 3.5 Ensure the SQL Server's MSSQL Service Account is Not an Administrator (Manual)
                        f.write('''<tr>
                                                                  <td>3.5 Ensure the SQL Server's MSSQL Service Account is Not an Administrator (Manual)'</td>
                                                                  <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 3.6 Ensure the SQL Server's SQLAgent Service Account is Not an Administrator (Manual)
                        f.write('''<tr>
                                                                  <td>3.6 Ensure the SQL Server's SQLAgent Service Account is Not an Administrator</td>
                                                                  <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 3.7 Ensure the SQL Server?s Full-Text Service Account is Not an Administrator (Manual)
                        f.write('''<tr>
                                                                 <td>3.7 Ensure the SQL Server's Full-Text Service Account is Not an Administrator (Manual)</td>
                                                                 <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Automated)
                        cursor.execute("""SELECT *
                                                  FROM master.sys.server_permissions
                                                  WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE
                                                  'GRANT%')
                                                  AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and
                                                  class_desc = 'SERVER')
                                                  AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                                                  class_desc = 'ENDPOINT' and major_id = 2)
                                                  AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                                                  class_desc = 'ENDPOINT' and major_id = 3)
                                                  AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                                                  class_desc = 'ENDPOINT' and major_id = 4)
                                                  AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                                                  class_desc = 'ENDPOINT' and major_id = 5);""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 3.9 Ensure Windows BUILTIN groups are not SQL Logins (Automated)
                        cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
                                                  FROM sys.server_principals pr
                                                  JOIN sys.server_permissions pe
                                                  ON pr.principal_id = pe.grantee_principal_id
                                                  WHERE pr.name like 'BUILTIN%';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>3.9 Ensure Windows BUILTIN groups are not SQL Logins (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                  </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>3.9 Ensure Windows BUILTIN groups are not SQL Logins (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1;

                        # 3.10 Ensure Windows local groups are not SQL Logins (Automated)
                        cursor.execute("USE master")
                        cursor.execute("""SELECT pr.[name], pe.[permission_name], pe.[state_desc]
                                                  FROM sys.server_principals pr
                                                  JOIN sys.server_permissions pe
                                                  ON pr.[principal_id] = pe.[grantee_principal_id]
                                                  WHERE pr.[type_desc] = 'WINDOWS_GROUP'
                                                  AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>3.10 Ensure Windows local groups are not SQL Logins (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1
                        else:
                            f.write('''<tr>
                                                                      <td>3.10 Ensure Windows local groups are not SQL Logins (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                </tr>''')
                            Failed += 1;

                        # 3.11 Ensure the public role in the msdb database is not granted acces to SQL Agent proxies (Automated)
                        cursor.execute("USE msdb")
                        cursor.execute("""SELECT sp.name AS proxyname
                                                  FROM dbo.sysproxylogin spl
                                                  JOIN sys.database_principals dp
                                                  ON dp.sid = spl.sid
                                                  JOIN sysproxies sp
                                                  ON sp.proxy_id = spl.proxy_id
                                                  WHERE principal_id = USER_ID('public');""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                     <td>3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Automated)</td>
                                                                      <td class="status-Failed">Failed</td>
                                                                </tr>''')
                            Failed += 1

                        # 3.12 Ensure the 'SYSADMIN' Role is Limited to Administrative or Built-in Accounts (Manual)
                        f.write('''<tr>
                                                                  <td>3.12 Ensure the 'SYSADMIN' Role is Limited to Administrative or Built-in Accounts (Manual)</td>
                                                                  <td class="status-manual">Manual</td>
                                                              </tr>''')
                        Manual += 1

                        # 3.13 Ensure membership in admin roles in MSDB database is limited (Automated)

                        cursor.execute("USE msdb")
                        cursor.execute("""SELECT count(*)
                                                  FROM sys.database_role_members AS drm
                                                  INNER JOIN sys.database_principals AS r
                                                  ON drm.role_principal_id = r.principal_id
                                                  INNER JOIN sys.database_principals AS m
                                                  ON drm.member_principal_id = m.principal_id
                                                  WHERE r.name in ('db_owner, db_securityadmin, db_ddladmin, db_datawriter')
                                                  and m.name <>'dbo';""")
                        row = cursor.fetchone()
                        if row[0] == 0:
                            f.write('''<tr>
                                                                     <td>3.13 Ensure membership in admin roles in MSDB database is limited (Automated)</td>
                                                                     <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>3.13 Ensure membership in admin roles in MSDB database is limited (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # Close the first table
                        f.write("</table>")

                        ##########################################4. Password Policies #####################################################

                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                    <strong>4. Password Policies</strong>
                                                                                 </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                        <th>Check</th>
                                                                        <th>Status</th>
                                                                    </tr>''')

                        f.write('''<tr>
                                                                  <td>4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Manual)</td>
                                                                  <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Automated)

                        cursor.execute("USE master")
                        cursor.execute("""SELECT l.[name], 'sysadmin membership' AS 'Access_Method'
                                                  FROM sys.sql_logins AS l
                                                  WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
                                                  AND l.is_expiration_checked <> 1
                                                  UNION ALL
                                                  SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
                                                  FROM sys.sql_logins AS l
                                                  JOIN sys.server_permissions AS p
                                                  ON l.principal_id = p.grantee_principal_id
                                                  WHERE p.type = 'CL' AND p.state IN ('G', 'W')
                                                  AND l.is_expiration_checked <> 1;""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Automated))</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Automated
                        cursor.execute("""SELECT name, is_disabled
                                                  FROM sys.sql_logins
                                                  WHERE is_policy_checked = 0;""")
                        row = cursor.fetchone()

                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                  </tr>''')
                            Failed += 1

                        # Close the first table
                        f.write("</table>")

                        ##########################################5. Auditing and logging #####################################################
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                                   <strong>5.Auditing and Logging </strong>
                                                                                                </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                         <th>Check</th>
                                                                         <th>Status</th>
                                                                    </tr>''')

                        # 5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Automated)
                        cursor.execute("USE master")
                        sql = """
                                                  DECLARE @NumErrorLogs int;
                                                  EXEC master.sys.xp_instance_regread
                                                  N'HKEY_LOCAL_MACHINE',
                                                  N'Software\Microsoft\MSSQLServer\MSSQLServer',
                                                  N'NumErrorLogs',
                                                  @NumErrorLogs OUTPUT;
                                                  SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
                                                  """
                        cursor.execute(sql)

                        try:
                            row = cursor.fetchone()

                            if row[0] >= 12:
                                f.write('''<tr>
                                                                          <td>5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Automated)</td>
                                                                          <td class="status-passed">Passed</td>
                                                                      </tr>''')
                                Passed += 1

                            else:
                                f.write('''<tr>
                                                                          <td>5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Automated)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1

                        except pyodbc.ProgrammingError:
                            f.write('''<tr>
                                                                     <td>5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Automated)
                        cursor.execute("""SELECT name,
                                                  CAST(value as int) as value_configured,
                                                  CAST(value_in_use as int) as value_in_use
                                                  FROM sys.configurations
                                                  WHERE name = 'default trace enabled';""")
                        row = cursor.fetchone()

                        if row[1] == 1 and row[2] == 1:

                            f.write('''<tr>
                                                                      <td>5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                  </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 5.3 Ensure 'Login Auditing' is set to 'failed logins' (Automated)
                        cursor.execute("""EXEC xp_loginconfig 'audit level';""")
                        row = cursor.fetchone()

                        if row[1] == "failure":
                            f.write('''<tr>
                                                                      <td>5.3 Ensure 'Login Auditing' is set to 'failed logins' (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1
                        else:
                            f.write('''<tr>
                                                                      <td>5.3 Ensure 'Login Auditing' is set to 'failed logins' (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                  </tr>''')
                            Failed += 1

                        # Close the first table
                        f.write("</table>")

                        ##########################################6.Application Development #####################################################
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                       <strong>6.Application Development</strong> </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                        <th>Check</th>
                                                                        <th>Status</th>
                                                                    </tr>''')
                        f.write('''<tr>
                                                                  <td>6.1 Ensure Database and Application User Input is Sanitized (Manual)</td>
                                                                  <td class="status-manual">Manual</td>
                                                             </tr>''')
                        Manual += 1

                        # 6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Automated)
                        cursor.execute("USE master")
                        sql = """
                                                  DECLARE @NumErrorLogs int;
                                                  EXEC master.sys.xp_instance_regread
                                                  N'HKEY_LOCAL_MACHINE',
                                                  N'Software\Microsoft\MSSQLServer\MSSQLServer',
                                                  N'NumErrorLogs',
                                                  @NumErrorLogs OUTPUT;
                                                  SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
                                                  """
                        cursor.execute(sql)

                        if cursor.rowcount == -1:
                            f.write('''<tr>
                                                                      <td>6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            x = True
                            i = 0

                            while i <= len(row):

                                if row[0][1] == "SAFE_ACCESS":
                                    i += 1
                                    Passed += 1;
                                    continue
                                else:
                                    x = False
                                    Failed += 1;
                                    break

                            if x == True:
                                f.write('''<tr>
                                                                          <td>6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Automated)</td>
                                                                          <td class="status-passed">Passed</td>
                                                                    </tr>''')
                                Passed += 1
                            else:
                                f.write('''<tr>
                                                                           <td>6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Automated)</td>
                                                                           <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1

                        # Close the first table
                        f.write("</table>")

                        ##########################################7. Encryption #####################################################
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                       <strong>7.Encryption</strong> </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                        <th>Check</th>
                                                                        <th>Status</th>
                                                                    </tr>''')

                        # 7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Automated)
                        i = 0
                        while i < len(userdbNames):

                            cursor.execute("USE " + userdbNames[i])
                            cursor.execute("""SELECT db_name() AS Database_Name, name AS Key_Name
                                                      FROM sys.symmetric_keys
                                                      WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
                                                      AND db_id() > 4;""")

                            row = cursor.fetchone()

                            if cursor.rowcount != 0:
                                f.write('''<tr>
                                                                          <td>7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Automated)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1
                                break
                            else:
                                if i == len(userdbNames) - 1:
                                    f.write('''<tr>
                                                                              <td>7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                         </tr>''')
                                    Passed += 1

                            i += 1

                        # 7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Automated)
                        i = 0
                        while i < len(userdbNames):

                            cursor.execute("USE " + userdbNames[i])
                            cursor.execute("""SELECT db_name() AS Database_Name, name AS Key_Name
                                                      FROM sys.asymmetric_keys
                                                      WHERE key_length < 2048
                                                      AND db_id() > 4;""")

                            row = cursor.fetchone()
                            if cursor.rowcount != 0:
                                f.write('''<tr>
                                                                         <td>7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Automated)</td>
                                                                         <td class="status-failed">Failed</td>
                                                                     </tr>''')
                                Failed += 1

                                break
                            else:
                                if i == len(userdbNames) - 1:
                                    f.write('''<tr>
                                                                              <td>7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                         </tr>''')
                                    Passed += 1

                            i += 1

                        # 7.3 Ensure Database Backups are Encrypted (Automated)
                        cursor.execute("""SELECT
                                                  b.key_algorithm, b.encryptor_type, d.is_encrypted,
                                                  b.database_name,
                                                  b.server_name
                                                  FROM msdb.dbo.backupset b
                                                  inner join sys.databases d on b.database_name = d.name
                                                  where b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted
                                                  = 0;""")
                        row = cursor.fetchone()
                        if cursor.rowcount == 0:
                            f.write('''<tr>
                                                                      <td>7.3 Ensure Database Backups are Encrypted (Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                  </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                      <td>7.3 Ensure Database Backups are Encrypted (Automated)</td>
                                                                      <td class="status-failed">Failed</td>
                                                                 </tr>''')
                            Failed += 1

                        # 7.4 Ensure Network Encryption is Configured and Enabled (Automated)
                        cursor.execute("USE master")
                        sql = """select distinct(encrypt_option) from sys.dm_exec_connections;"""
                        cursor.execute(sql)
                        row = cursor.fetchone()

                        if row[-1] == "TRUE":
                            f.write('''<tr>
                                                                      <td>7.4 Ensure Network Encryption is Configured and Enabled(Automated)</td>
                                                                      <td class="status-passed">Passed</td>
                                                                 </tr>''')
                            Passed += 1

                        else:
                            f.write('''<tr>
                                                                     <td>7.4 Ensure Network Encryption is Configured and Enabled(Automated)</td>
                                                                     <td class="status-failed">Failed</td>
                                                                  </tr>''')

                            Failed += 1;

                        # Close the first table
                        f.write("</table>")

                        ##########################################  Appendix: Additional Considerations #####################################################
                        f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                      <strong>8 Appendix: Additional Considerations</strong> </p>''')

                        # Start the table
                        f.write('''<table>
                                                                    <tr>
                                                                        <th>Check</th>
                                                                        <th>Status</th>
                                                                    </tr>''')
                        f.write('''<tr>
                                                                  <td>8.1 Ensure 'SQL Server Browser Service' is configured correctly (Manual)</td>
                                                                  <td class="status-manual">Manual</td>
                                                            </tr>''')
                        Manual += 1

                        # Close the first table
                        f.write("</table>")

                        # Open the table after all rows are written
                        f.write('''<table class="summary-table" style="width: 100%; margin-top: 20px; border-collapse: collapse;">
                                                               <tr>
                                                                   <th>Total Passed</th>
                                                                   <th>Total Failed</th>
                                                                   <th>Total Manual</th>
                                                                   <th>No Permission</th>
                                                               </tr>
                                                               <tr>
                                                                   <td class="status-passed" style="text-align: center;">{}</td>
                                                                   <td class="status-failed" style="text-align: center;">{}</td>
                                                                   <td class="status-manual" style="text-align: center;">{}</td>
                                                                   <td class="status-nopermission" style="text-align: center;">{}</td>
                                                               </tr>
                                                             </table>
                                                                 <footer style="text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0;">
                                                                     <p>2024 All Rights Reserved to Secure Auditix tool</p>
                                                                     <p>Coded and UI Designed by <strong>Mandavalli Ganesh<strong></p>
                                                                 </footer>
                                                          </body>
                                                      </html>'''.format(Passed, Failed, Manual, NoPermission, Passed,
                                                                        Failed,
                                                                        Manual,
                                                                        NoPermission))
                        # Return the HTML file as a downloadable attachment
                        with open(file_path, 'r') as file:
                            response = HttpResponse(file.read(), content_type='text/html')
                            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                            return response

                    elif selected_standard == "DISA_STIG":
                        # Run DISA STIG-related queries
                        # Start writing the results in it

                        cursor.execute("""select @@version;""")

                        row = cursor.fetchone()

                        version = []

                        while row:
                            version.append(row[0])
                            row = cursor.fetchone()

                        string = ""

                        # Starting a for loop to traverse through the list elements
                        for element in version:
                            string = string + " " + element  # Using " " as a separator for the elements of the string. However, it will add an extra space at the beginning of the string

                        # Write the string inside a paragraph with some styling
                        f.write(f'''<div class="info-box">
                                                           <p><strong>{string}</strong><br> </p> 
                                                      </div>''')

                        # Add a horizontal line for separation
                        f.write("<hr style='border: 1px solid #00008B; margin: 20px 0;'>\n")

                        # Write the additional messages in paragraph tags
                        f.write(
                            "<p style='font-weight: bold; color: #00008B;'>Database Auditing - DISA STIG is coming soon...</p>\n")
                        f.write("<p>Currently under maintenance, Update is coming in next release.</p>\n")
                        f.write("<p>Thank you - Please Visit again.</p>\n")

                        # Close the table and add the footer

                        # Return the HTML file as a downloadable attachment
                        with open(file_path, 'r') as file:
                            response = HttpResponse(file.read(), content_type='text/html')
                            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                            return response

                # Close the connection after operations
                conn.close()
            elif db_type == "Postgresql":
                try:
                    # Assuming 'selected_standard', 'server', 'database', 'username', and 'password' are provided from user input
                    if selected_standard == "CIS":
                        server_parts = server.split(",")
                        if len(server_parts) != 2:
                            message = "Please specify both host and port as host,port."
                            return

                        host = server_parts[0]
                        port = server_parts[1]

                        try:
                            # Connect to PostgreSQL with specified host and port
                            connection = psycopg2.connect(
                                host=host,
                                port=port,
                                dbname=database,
                                user=username,
                                password=password
                            )


                            # Create a cursor and execute a query
                            cursor = connection.cursor()

                            # Get the current datetime for the report header
                            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                            # Define file path inside Django's media directory
                            file_name = "Postgres_SQL_results.htm"
                            file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                            # Ensure MEDIA_ROOT exists
                            os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

                            # Open the file for writing (HTML structure)
                            with open(file_path, "w") as f:
                                # Write the initial HTML structure
                                f.write(f"""<html lang="en">
                                                                                    <head>
                                                                                       <meta charset="UTF-8">
                                                                                       <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                                                                       <title>Audit Report</title>
                                                                                       <style>
                                                                                          body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                                                                          .header {{ text-align: right; font-size: 14px; margin-bottom: 10px; }}
                                                                                          .info-box {{ background-color: #f2f2f2; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }}
                                                                                          h2 {{ color: #00008B; text-align: center; margin-top: 20px; }}
                                                                                          h3 {{ color: #00008B; text-align: left; margin-top: 20px; }}
                                                                                          table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                                                                                          table, th, td {{ border: 1px solid #ddd; }}
                                                                                          th, td {{ padding: 12px; text-align: left; }}
                                                                                          th {{ background-color: #00008B; color: white; }}
                                                                                          tr:nth-child(even) {{ background-color: #f2f2f2; }}
                                                                                          .status-passed {{ color: green; }}
                                                                                          .status-failed {{ color: red; }}
                                                                                          .status-manual {{ color: black; }}
                                                                                          .status-nopermission {{ color: yellow; }}
                                                                                          .footer {{ text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0; }}
                                                                                       </style>
                                                                                  </head>
                                                                                  <body>
                                                                                      <div class="header"><strong>Audit Date: </strong>{current_datetime}</div>
                                                                                  """)

                                # Execute the query to fetch PostgreSQL version
                                cursor.execute("SELECT version();")
                                print("Executed SELECT version(); query.")

                                # Fetch the result
                                version_info = cursor.fetchall()
                                print("Fetched version info:", version_info)

                                # Loop through the result and write it into the HTML file
                                for row in version_info:
                                    f.write(f'''<div class="info-box">
                                                                                  <p><strong>{row[0]}</strong><br> </p> 
                                                                                 </div>''')

                                # Define status counters
                                Passed = 0
                                Failed = 0
                                Manual = 0
                                NoPermission = 0

                                # Write Audit Section Title
                                f.write(f"<h2>Database Audit Report - CIS PostgreSQL Benchmark</h2>")
                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                         <strong>1. PostgreSQL Database Installation and Patching </strong>  
                                                                                     </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                          <tr>
                                                                              <th>Check</th>
                                                                              <th>Status</th>
                                                                          </tr>''')

                                # 1.1 Ensure packages are obtained from authorized repositories (Manual)
                                f.write('''<tr>
                                                                       <td>1.1 Ensure packages are obtained from authorized repositories (Manual)</td>
                                                                       <td class="status-manual">Manual</td>
                                                                </tr>''')
                                Manual += 1

                                try:
                                    # 1.2 Ensure systemd Service Files Are Enabled (Automated)
                                    service_query = subprocess.run(
                                        'sc query type= service | findstr /I "postgres"',
                                        capture_output=True, text=True, shell=True
                                    )

                                    if not service_query.stdout.strip():
                                        f.write('''<tr>
                                                                            <td>1.2 Ensure systemd Service Files Are Enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                          </tr>''')
                                        Failed += 1
                                    else:
                                        service_name = service_query.stdout.split()[1]  # Extract service name
                                        start_type_query = subprocess.run(
                                            f'sc qc "{service_name}" | findstr "START_TYPE"',
                                            capture_output=True, text=True, shell=True
                                        )

                                        start_type_line = start_type_query.stdout.strip()

                                        if start_type_line:
                                            start_type = start_type_line.split(":")[1].strip().split()[0]
                                            try:
                                                start_type = int(start_type)  # Convert string to integer
                                            except ValueError:
                                                print(f"Error parsing start type: {start_type_line}")
                                                start_type = None
                                        else:
                                            start_type = None

                                        if start_type == 4:
                                            f.write('''<tr>
                                                                                <td>1.2 Ensure systemd Service Files Are Enabled (Automated)</td>
                                                                                <td class="status-failed">Failed</td>
                                                                            </tr>''')
                                            Failed += 1
                                        else:
                                            f.write('''<tr>
                                                                                  <td>1.2 Ensure systemd Service Files Are Enabled (Automated)</td>
                                                                                  <td class="status-passed">Passed</td>
                                                                              </tr>''')
                                            Passed += 1

                                except psycopg2.DatabaseError as e:
                                    # Display error if connection fails
                                    f.write('''<tr>
                                                                        <td>1.2 Ensure systemd Service Files Are Enabled (Automated)</td>
                                                                         <td class="status-nopermission">NoPermission</td>
                                                                      </tr>''')
                                    NoPermission += 1

                                try:
                                    # Directory to check
                                    directory = r"C:\Program Files\PostgreSQL\16\data"

                                    # Initialize status
                                    status = "Passed"

                                    # Check if the directory exists
                                    if not os.path.exists(directory) or not os.path.isdir(directory):
                                        status = "Failed"  # Directory not found or not accessible

                                    # Command to get directory permissions
                                    command = f'icacls "{directory}"'
                                    result = subprocess.run(command, capture_output=True, text=True, shell=True)

                                    # Debugging: Print the raw icacls output
                                    print("ICACLS Output:")
                                    print(result.stdout)

                                    # If the directory exists and icacls command ran successfully
                                    if result.returncode == 0 and status == "Passed":
                                        output = result.stdout.strip().splitlines()

                                        # Required permissions (adjusted for inheritable permissions)
                                        required_permissions = [
                                            "NT SERVICE\\PostgreSQL:(OI)(CI)(F)",
                                            "NT AUTHORITY\\SYSTEM:(OI)(CI)(F)",
                                            "BUILTIN\\Administrators:(OI)(CI)(F)"
                                        ]

                                        # Debugging: Check if required permissions are in the output
                                        print("Checking permissions...")
                                        for permission in required_permissions:
                                            matched = False
                                            for line in output:
                                                print(f"Checking line: {line.strip()}")  # Print each line to compare

                                                # Adjust the check for inheritable permissions or any variant
                                                if permission in line.strip() or line.strip().startswith(permission.split(":")[0]):
                                                    matched = True
                                                    break

                                            if not matched:
                                                print(f"Permission check failed for: {permission}")
                                                status = "Failed"  # Permission check failed

                                    # Write result to file based on the status
                                    if status == "Failed":
                                        f.write('''<tr>
                                                                            <td>1.3 Ensure Data Cluster Initialized Successfully (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>
                                                                        <tr>
                                                                             <td colspan="2"><strong>NOTE:</strong> 1.3 It will work for the Admin, but the current user might not have the required permission.</td>
                                                                        </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>1.3 Ensure Data Cluster Initialized Successfully (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    # General exception for PostgreSQL error handling
                                    f.write('''<tr>
                                                                        <td>1.3 Ensure Data Cluster Initialized Successfully (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')
                                    NoPermission += 1


                                # Close the table
                                f.write("</table>")

                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                  <strong>2. Directory and File Permissions</strong>  
                                                                </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                          <tr>
                                                                              <th>Check</th>
                                                                              <th>Status</th>
                                                                          </tr>''')

                                # 2.1 Ensure the file permissions mask is correct (Manual)
                                f.write('''<tr>
                                                                      <td>2.1 Ensure the file permissions mask is correct (Manual for Linux)</td>
                                                                      <td class="status-manual">No Need</td>
                                                                  </tr>''')

                                # Close the table
                                f.write("</table>")

                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                            <strong>3. Logging And Auditing</strong>  
                                                                                        </p>''')

                                f.write('''<p style="color: #00008B; font-size: 19px; text-align: left; margin-top: 19px;">
                                                                                              <strong>3.1 PostgreSQL Logging</strong>  
                                                                                        </p>''')

                                f.write('''<p style="color: #00008B; font-size: 19px; text-align: left; margin-top: 19px;">
                                                                                  <strong>3.1.1 Logging Rationale</strong>  
                                                                 </p>''')

                                f.write('''<table>
                                                                        <tr>
                                                                            <th>Check</th>
                                                                            <th>Status</th>
                                                                        </tr>''')
                                # 3.1.2 Ensure the log destinations are set correctly (Automated)
                                try:
                                    cursor.execute("show log_destination;")
                                    row = cursor.fetchone()

                                    if cursor.rowcount == 0:
                                        f.write('''<tr>
                                                                              <td>3.1.2 Ensure the log destinations are set correctly (Automated)</td>
                                                                               <td class="status-failed">Failed</td>
                                                                         </tr>''')
                                        Failed +=1

                                    else:
                                        f.write('''<tr>
                                                                              <td>3.1.2 Ensure the log destinations are set correctly (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                              </tr>''')
                                        Passed +=1

                                except Exception as e:
                                    # General exception for PostgreSQL error handling
                                    f.write('''<tr>
                                                                        <td>3.1.2 Ensure the log destinations are set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')
                                    NoPermission += 1

                                # 3.1.3 Ensure the logging collector is enabled (Automated)
                                try:
                                    cursor.execute("show logging_collector;")
                                    row = cursor.fetchone()

                                    if row[0].strip().lower() == 'on':
                                        f.write('''<tr>
                                                                              <td> 3.1.3 Ensure the logging collector is enabled (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                          </tr>''')

                                        Passed +=1

                                    else:
                                        f.write('''<tr>
                                                                              <td>3.1.3 Ensure the logging collector is enabled (Automated)</td>
                                                                              <td class="status-failed">Failed</td>
                                                                          </tr>''')
                                        Failed +=1

                                except Exception as e:
                                    # General exception for PostgreSQL error handling
                                    f.write('''<tr>
                                                                          <td>3.1.2 Ensure the log destinations are set correctly (Automated)</td>
                                                                          <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.4 Ensure the log file destination directory is set correctly (Automated)
                                try:
                                    # Execute the SQL query to check the log directory setting
                                    cursor.execute("SHOW log_directory;")
                                    row = cursor.fetchone()

                                    # Define the expected log directory (relative or absolute, based on your requirement)
                                    expected_log_directory = 'log'  # For relative paths, you can adjust to '/var/log/pg_log' for absolute

                                    # Check if log_directory is set to the expected value
                                    if row[0].strip().lower() == expected_log_directory.lower():
                                        f.write('''<tr>
                                                                            <td>3.1.4 Ensure the log file destination directory is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.4 Ensure the log file destination directory is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.4 Ensure the log file destination directory is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                try:
                                    # Execute the SQL query to check the log filename setting
                                    cursor.execute("SHOW log_filename;")
                                    row = cursor.fetchone()

                                    # Get the actual log filename pattern
                                    actual_log_filename = row[0].strip().lower()

                                    # Check if the filename ends with '.log'
                                    if actual_log_filename.endswith('.log'):
                                        f.write('''<tr>
                                                                            <td>3.1.5 Ensure the filename pattern for log files is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.5 Ensure the filename pattern for log files is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.5 Ensure the filename pattern for log files is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.6 Ensure the log file permissions are set correctly (Automated)

                                #0600: Allows only the server owner to read and write the log files.
                                #0640: Allows members of the server owner’s group to read the log files.
                                #Both are acceptable.
                                try:
                                    # Execute the SQL query to check the log file mode setting
                                    cursor.execute("SHOW log_file_mode;")
                                    row = cursor.fetchone()

                                    # Define the expected log file modes
                                    expected_log_file_mode = ['0600', '0640']

                                    # Check if log_file_mode is in the list of expected values
                                    if row[0].strip() in expected_log_file_mode:
                                        f.write('''<tr>
                                                                            <td>3.1.6 Ensure the log file permissions are set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.6 Ensure the log file permissions are set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.6 Ensure the log file permissions are set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.7 Ensure 'log_truncate_on_rotation' is enabled (Automated)
                                try:
                                    # Execute the SQL query to check the log_truncate_on_rotation setting
                                    cursor.execute("SHOW log_truncate_on_rotation;")
                                    row = cursor.fetchone()

                                    # Check if log_truncate_on_rotation is set to 'on'
                                    if row[0].strip().lower() == 'on':
                                        f.write('''<tr>
                                                                            <td>3.1.7 Ensure 'log_truncate_on_rotation' is enabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.7 Ensure 'log_truncate_on_rotation' is enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.7 Ensure 'log_truncate_on_rotation' is enabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.8 Ensure the maximum log file lifetime is set correctly (Automated)
                                try:
                                    # Execute the SQL query to check the log rotation age setting
                                    cursor.execute("SHOW log_rotation_age;")
                                    row = cursor.fetchone()

                                    # Define the acceptable log rotation ages
                                    acceptable_log_rotation_ages = ["1d", "1440"]

                                    # Strip any extra spaces from the value and check if it matches an acceptable value
                                    if row[0].strip() in acceptable_log_rotation_ages:
                                        f.write('''<tr>
                                                                            <td>3.1.8 Ensure the maximum log file lifetime is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.8 Ensure the maximum log file lifetime is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.8 Ensure the maximum log file lifetime is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.1.9 Ensure the maximum log file size is set correctly (Automated)

                                try:
                                    # Execute the SQL query to check the log rotation size setting
                                    cursor.execute("SHOW log_rotation_size;")
                                    row = cursor.fetchone()

                                    # Check if the log_rotation_size is greater than 0
                                    if row[0].strip() != "0":
                                        f.write('''<tr>
                                                                            <td>3.1.9 Ensure the maximum log file size is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.9 Ensure the maximum log file size is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.9 Ensure the maximum log file size is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3 .1.10 Ensure the correct syslog facility is selected (Manual)
                                try:
                                    # Execute the SQL query to check the syslog facility setting
                                    cursor.execute("SHOW syslog_facility;")
                                    row = cursor.fetchone()

                                    # Define the acceptable syslog facilities (adjust as per policy)
                                    acceptable_syslog_facilities = ["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]

                                    # Check if the syslog facility is in the acceptable list
                                    if row[0].strip().upper() in acceptable_syslog_facilities:
                                        f.write('''<tr>
                                                                            <td>3.1.10 Ensure the correct syslog facility is selected (Manual)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.10 Ensure the correct syslog facility is selected (Manual)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.10 Ensure the correct syslog facility is selected (Manual)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.1.11 Ensure syslog messages are not suppressed (Automated)
                                try:
                                    # Execute the SQL query to check the syslog sequence numbers setting
                                    cursor.execute("SHOW syslog_sequence_numbers;")
                                    row = cursor.fetchone()

                                    # Check if syslog_sequence_numbers is enabled (set to 'on')
                                    if row[0].strip().lower() == "on":
                                        f.write('''<tr>
                                                                            <td>3.1.11 Ensure syslog messages are not suppressed (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.11 Ensure syslog messages are not suppressed (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.11 Ensure syslog messages are not suppressed (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.12 Ensure syslog messages are not lost due to size (Automated)
                                try:
                                    # Execute the SQL query to check the syslog split messages setting
                                    cursor.execute("SHOW syslog_split_messages;")
                                    row = cursor.fetchone()

                                    # Check if syslog_split_messages is enabled (set to 'on')
                                    if row[0].strip().lower() == "on":
                                        f.write('''<tr>
                                                                            <td>3.1.12 Ensure syslog messages are not lost due to size (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.12 Ensure syslog messages are not lost due to size (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.12 Ensure syslog messages are not lost due to size (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.13 Ensure the program name for PostgreSQL syslog messages is correct
                                try:
                                    # Execute the SQL query to check the syslog_ident setting
                                    cursor.execute("SHOW syslog_ident;")
                                    row = cursor.fetchone()

                                    # Check if syslog_ident is set to 'postgres'
                                    if row[0].strip().lower() == "postgres":
                                        f.write('''<tr>
                                                                            <td>3.1.13 Ensure the program name for PostgreSQL syslog messages is correct (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.13 Ensure the program name for PostgreSQL syslog messages is correct (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.13 Ensure the program name for PostgreSQL syslog messages is correct (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.14 Ensure the correct messages are written to the server log (Automated)
                                valid_levels = ["debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice",
                                                "warning", "error", "log", "fatal", "panic"]

                                try:
                                    # Execute the SQL query to check the log_min_messages setting
                                    cursor.execute("SHOW log_min_messages;")
                                    row = cursor.fetchone()

                                    # Check if log_min_messages is set to one of the acceptable values (default is warning)
                                    if row[0].strip().lower() in valid_levels:
                                        f.write('''<tr>
                                                                              <td>3.1.14 Ensure the correct messages are written to the server log (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                          </tr>''')
                                        Passed += 1

                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.14 Ensure the correct messages are written to the server log (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.14 Ensure the correct messages are written to the server log (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.15 Ensure the correct SQL statements generating errors are recorded (Automated)

                                valid_levels = ["debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error", "log", "fatal", "panic"]

                                try:
                                    # Execute the SQL query to check the log_min_error_statement setting
                                    cursor.execute("SHOW log_min_error_statement;")
                                    row = cursor.fetchone()

                                    # Check if log_min_error_statement is set to one of the acceptable values
                                    if row[0].strip().lower() in valid_levels:
                                        f.write('''<tr>
                                                                              <td>3.1.15 Ensure the correct SQL statements generating errors are recorded (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                      </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.15 Ensure the correct SQL statements generating errors are recorded (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.15 Ensure the correct SQL statements generating errors are recorded (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.16 Ensure 'debug_print_parse' is disabled (Automated)
                                try:
                                    # Execute the SQL query to check the debug_print_parse setting
                                    cursor.execute("SHOW debug_print_parse;")
                                    row = cursor.fetchone()

                                    # Check if debug_print_parse is set to 'off'
                                    if row[0].strip().lower() == "off":
                                        f.write('''<tr>
                                                                            <td>3.1.16 Ensure 'debug_print_parse' is disabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.16 Ensure 'debug_print_parse' is disabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.16 Ensure 'debug_print_parse' is disabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.1.17 Ensure 'debug_print_rewritten' is disabled (Automated)
                                try:
                                    # Execute the SQL query to check the debug_print_rewritten setting
                                    cursor.execute("SHOW debug_print_rewritten;")
                                    row = cursor.fetchone()

                                    # Check if debug_print_rewritten is set to 'off'
                                    if row[0].strip().lower() == "off":
                                        f.write('''<tr>
                                                                            <td>3.1.17 Ensure 'debug_print_rewritten' is disabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.17 Ensure 'debug_print_rewritten' is disabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.17 Ensure 'debug_print_rewritten' is disabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.1.18 Ensure 'debug_print_plan' is disabled (Automated)
                                try:
                                    # Execute the SQL query to check the debug_print_plan setting
                                    cursor.execute("SHOW debug_print_plan;")
                                    row = cursor.fetchone()

                                    # Check if debug_print_plan is set to 'off'
                                    if row[0].strip().lower() == "off":
                                        f.write('''<tr>
                                                                            <td>3.1.18 Ensure 'debug_print_plan' is disabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.18 Ensure 'debug_print_plan' is disabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.18 Ensure 'debug_print_plan' is disabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.19 Ensure 'debug_pretty_print' is enabled (Automated)
                                try:
                                    # Execute the SQL query to check the debug_pretty_print setting
                                    cursor.execute("SHOW debug_pretty_print;")
                                    row = cursor.fetchone()

                                    # Check if debug_pretty_print is set to 'on'
                                    if row[0].strip().lower() == "on":
                                        f.write('''<tr>
                                                                            <td>3.1.19 Ensure 'debug_pretty_print' is enabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.19 Ensure 'debug_pretty_print' is enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.19 Ensure 'debug_pretty_print' is enabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.20 Ensure 'log_connections' is enabled (Automated)
                                try:
                                    # Execute the SQL query to check the log_connections setting
                                    cursor.execute("SHOW log_connections;")
                                    row = cursor.fetchone()

                                    # Check if log_connections is set to 'on'
                                    if row[0].strip().lower() == "on":
                                        f.write('''<tr>
                                                                            <td>3.1.20 Ensure 'log_connections' is enabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.20 Ensure 'log_connections' is enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.20 Ensure 'log_connections' is enabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.1.21 Ensure 'log_disconnections' is enabled (Automated)

                                try:
                                    # Execute the SQL query to check the log_disconnections setting
                                    cursor.execute("SHOW log_disconnections;")
                                    row = cursor.fetchone()

                                    # Check if log_disconnections is set to 'on'
                                    if row[0].strip().lower() == "on":
                                        f.write('''<tr>
                                                                            <td>3.1.21 Ensure 'log_disconnections' is enabled (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.21 Ensure 'log_disconnections' is enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.21 Ensure 'log_disconnections' is enabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.22 Ensure 'log_error_verbosity' is set to 'verbose' (Automated)
                                # TERSE: Logs the least information (fails based on your description).
                                # DEFAULT: Provides a moderate level of information, but fails in this case, as it does not meet the required setting of VERBOSE.
                                # VERBOSE: Provides the most detailed logging, which is the recommended setting.

                                try:
                                    # Execute the SQL query to check the log_error_verbosity setting
                                    cursor.execute("SHOW log_error_verbosity;")
                                    row = cursor.fetchone()

                                    # Check if log_error_verbosity is set to 'verbose'
                                    if row[0].strip().lower() == "verbose":
                                        f.write('''<tr>
                                                                            <td>3.1.22 Ensure 'log_error_verbosity' is set to 'verbose' (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.22 Ensure 'log_error_verbosity' is set to 'verbose' (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.22 Ensure 'log_error_verbosity' is set to 'verbose' (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.23 Ensure 'log_hostname' is set correctly (Automated)
                                try:
                                    # Execute the SQL query to check the log_hostname setting
                                    cursor.execute("SHOW log_hostname;")
                                    row = cursor.fetchone()

                                    # Check if log_hostname is set to 'off'
                                    if row[0].strip().lower() == "off":
                                        f.write('''<tr>
                                                                            <td>3.1.23 Ensure 'log_hostname' is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.23 Ensure 'log_hostname' is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.23 Ensure 'log_hostname' is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.24 Ensure 'log_line_prefix' is set correctly (Automated)

                                # Check for %m [%p]: The first condition checks if %m [%p] is in the log_line_prefix.
                                # Validation for Non-Syslog Logging: It then checks if the required components for non-Syslog logging (db=%d, user=%u, app=%a, client=%h) are present in the log_line_prefix.
                                # Syslog Logging Check: If the log_line_prefix doesn't match the non-Syslog format but contains the required Syslog components (user=%u, db=%d, app=%a, client=%h), it will be marked as "Passed".
                                # Failure Case: If neither condition is met, it is marked as "Failed".

                                try:
                                    # Execute the SQL query to check the log_line_prefix setting
                                    cursor.execute("SHOW log_line_prefix;")
                                    row = cursor.fetchone()

                                    # Define the required components for non-Syslog and Syslog logging
                                    required_non_syslog = ["%m [%p]", "db=%d", "user=%u", "app=%a", "client=%h"]
                                    required_syslog = ["user=%u", "db=%d", "app=%a", "client=%h"]

                                    # Check if the log_line_prefix includes the required components
                                    if "%m [%p]" in row[0] and all(
                                            component in row[0] for component in required_non_syslog):
                                        f.write('''<tr>
                                                                            <td>3.1.24 Ensure 'log_line_prefix' is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    elif all(component in row[0] for component in required_syslog):
                                        f.write('''<tr>
                                                                            <td>3.1.24 Ensure 'log_line_prefix' is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>3.1.24 Ensure 'log_line_prefix' is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.24 Ensure 'log_line_prefix' is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # 3.1.25 Ensure 'log_statement' is set correctly (Automated)

                                try:
                                    # Execute the SQL query to check the log_statement setting
                                    cursor.execute("SHOW log_statement;")
                                    row = cursor.fetchone()

                                    # Check if log_statement is set to 'none'
                                    if row[0].strip().lower() == "none":
                                        f.write('''<tr>
                                                                            <td>3.1.25 Ensure 'log_statement' is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1
                                    else:
                                        # If it's not 'none', it's considered a pass
                                        f.write('''<tr>
                                                                            <td>3.1.25 Ensure 'log_statement' is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.25 Ensure 'log_statement' is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                try:
                                    # Execute the SQL query to check the log_timezone setting
                                    cursor.execute("SHOW log_timezone;")
                                    row = cursor.fetchone()

                                    # Check if a row is returned
                                    if row:
                                        # If a row is returned, it means the query was successful
                                        log_timezone_value = row[0]  # Store the returned value (log_timezone)
                                        f.write('''<tr>
                                                                            <td>3.1.26 Ensure 'log_timezone' is set correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                        </tr>''')

                                        # Write the note with the actual log_timezone value
                                        f.write(f'''<td><b>Note:</b> Returning the <b> <i>{log_timezone_value}.</b> </i> Check with your organization as defined by the logging policy.</td>''')
                                        Passed += 1
                                    else:
                                        # If no row is returned, it's considered a failure
                                        f.write('''<tr>
                                                                            <td>3.1.26 Ensure 'log_timezone' is set correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.1.26 Ensure 'log_timezone' is set correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                #3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled (Automated)
                                try:
                                    # Execute the SQL query to check the shared_preload_libraries setting
                                    cursor.execute("SHOW shared_preload_libraries;")
                                    row = cursor.fetchone()

                                    # Check if pgaudit is in shared_preload_libraries
                                    if row and "pgaudit" in row[0]:

                                        # Check the pgaudit.log setting
                                        cursor.execute("SHOW pgaudit.log;")
                                        pgaudit_log_row = cursor.fetchone()

                                        # Check if pgaudit.log exists
                                        if pgaudit_log_row:
                                            f.write('''<tr>
                                                                                  <td>3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled (Automated)</td>
                                                                                  <td class="status-passed">Passed</td>
                                                                           </tr>''')
                                            Passed +=1
                                        else:
                                            f.write('''<tr>
                                                                                <td>3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled (Automated)</td>
                                                                                <td class="status-failed">Failed</td>
                                                                            </tr>''')
                                            Failed += 1
                                    else:
                                        # If pgaudit is not found in shared_preload_libraries, it's a fail
                                        f.write('''<tr>
                                                                            <td>3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1

                                except Exception as e:
                                    # Handle any exceptions that occur during the check
                                    f.write('''<tr>
                                                                        <td>3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                     </tr>''')
                                    NoPermission += 1

                                # Close the table
                                f.write("</table>")

                                # 4 User Access and Authorization

                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                                                         <strong> 4. User Access and Authorization </strong>  
                                                                 </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                        <tr>
                                                                             <th>Check</th>
                                                                             <th>Status</th>
                                                                        </tr>''')

                                # 4.1 Ensure packages are obtained from authorized repositories (Manual)
                                f.write('''<tr>
                                                                      <td> 4.1 Ensure sudo is configured correctly (Manual)</td>
                                                                     <td class="status-nopermission">No Permission</td>
                                                                 </tr>''')
                                # Write the note
                                f.write(
                                    f'''<td><b>Note:</b> Need an administration priviliges </td>''')
                                NoPermission += 1

                                # 4.2 Ensure excessive administrative privileges are revoked (Manual)
                                f.write('''<tr>
                                                                      <td>4.2 Ensure excessive administrative privileges are revoked (Manual)</td>
                                                                      <td class="status-nopermission">No Permission</td>
                                                                  </tr>''')

                                # Write the note
                                f.write(
                                    f'''<td><b>Note:</b> Need an administration priviliges </td>''')
                                NoPermission += 1

                                # 4.3 Ensure excessive function privileges are revoked (Automated)
                                """postgres user is usually created during the installation of PostgreSQL,
                                   and it is often used for administrative tasks like system maintenance and backup."""
                                f.write('''<tr>
                                                                      <td>4.3 Ensure excessive function privileges are revoked (Automated)</td>
                                                                      <td class="status-nopermission">No Permission</td>
                                                                  </tr>''')
                                # Write the note
                                f.write(
                                    f'''<td><b>Note:</b> Need an POSTGRES user (Super user) priviliges </td>''')
                                NoPermission += 1

                                # 4.4 Ensure excessive DML privileges are revoked (Manual)
                                f.write('''<tr>
                                                                     <td>4.4 Ensure excessive DML privileges are revoked (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual += 1

                                """1. RLS Check for Tables: SELECT oid, relname FROM pg_class WHERE relrowsecurity IS TRUE; retrieves tables with RLS enabled. 
                                      If RLS is not configured on any tables, it’s marked as failed.
                                   2. Policy Check on Each Table: For each table with RLS, we query pg_policy to check policies applied to that table.
                                   3. Unauthorized Bypass RLS Check: Querying pg_authid with rolbypassrls = TRUE to identify unauthorized users with 
                                      the Bypass RLS privilege."""

                                # 4.5 Ensure Row Level Security (RLS) is configured correctly (Manual)
                                try:
                                    # Initialize audit status as passed
                                    rls_pass = True

                                    # Step 1: Check for tables with RLS enabled
                                    cursor.execute("SELECT oid, relname FROM pg_class WHERE relrowsecurity IS TRUE;")
                                    rls_tables = cursor.fetchall()

                                    if rls_tables:
                                        for table in rls_tables:
                                            oid, table_name = table

                                            # Step 2: Check for policies on each RLS-enabled table
                                            cursor.execute(f"SELECT polname FROM pg_policy WHERE polrelid = {oid};")
                                            policies = cursor.fetchall()

                                            # If any RLS-enabled table lacks policies, mark as failed
                                            if not policies:
                                                rls_pass = False
                                                break  # No need to check further tables if one already fails

                                        # Step 3: Check for unauthorized users with Bypass RLS privilege
                                        cursor.execute("SELECT rolname FROM pg_authid WHERE rolbypassrls = TRUE;")
                                        users_with_bypass_rls = cursor.fetchall()

                                        # If any unauthorized users have Bypass RLS, mark as failed
                                        if users_with_bypass_rls:
                                            rls_pass = False
                                    else:
                                        # No RLS-enabled tables found, mark as failed
                                        rls_pass = False

                                    # Pass: If all RLS-enabled tables have policies and no unauthorized users have bypass privileges.
                                    if rls_pass:
                                        f.write('''<tr>
                                                                              <td>4.5 Ensure Row Level Security (RLS) is configured correctly (Manual)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                         </tr>''')
                                        # Write the note
                                        f.write(f'''<td><b>Note:</b> The decision to implement Row Level Security (RLS) depends on an 
                                                                              organization's specific business processes and security needs.</td>''')
                                        Passed += 1
                                    else:
                                        # Fail: If any RLS-enabled table lacks a policy or unauthorized users have bypass privileges.
                                        f.write('''<tr>
                                                                              <td>4.5 Ensure Row Level Security (RLS) is configured correctly (Manual)</td>
                                                                              <td class="status-failed">Failed</td>
                                                                         </tr>''')
                                        # Write the note
                                        f.write(f'''<td><b>Note:</b> The decision to implement Row Level Security (RLS) depends on an 
                                                                              organization's specific business processes and security needs.</td>''')
                                        Failed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                        <td>4.5 Ensure Row Level Security (RLS) is configured correctly (Manual)</td>
                                                                        <td class="status-nopermission">No Permission</td>
                                                                    </tr>''')
                                    NoPermission += 1

                                # 4.6 Ensure the set_user extension is installed (Automated)
                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Step 1: Check if the 'set_user' extension is installed
                                    cursor.execute("SELECT * FROM pg_available_extensions WHERE name = 'set_user';")
                                    extension_check = cursor.fetchall()

                                    if not extension_check:
                                        # If 'set_user' extension is not available, mark as Failed
                                        result = "Failed"

                                    # Step 2: Identify superuser roles that can still log in (including roles starting/ending with admin)
                                    cursor.execute("SELECT rolname FROM pg_authid WHERE rolsuper AND rolcanlogin;")
                                    superuser_roles = cursor.fetchall()

                                    # List of patterns to consider as admin-like (roles starting or ending with admin)
                                    admin_patterns = [
                                        'admin',        # roles that contain 'admin' anywhere
                                        'administrator', # roles that contain 'administrator' anywhere
                                        'root',         # roles that contain 'root' anywhere
                                        'dbadmin',      # roles that contain 'dbadmin' anywhere
                                        'sysadmin',     # roles that contain 'sysadmin' anywhere
                                        '^admin.*',     # roles starting with 'admin'
                                        '.*admin$',     # roles ending with 'admin'
                                    ]

                                    for role in superuser_roles:
                                        if any(role[0].startswith(admin_pattern) or role[0].endswith(admin_pattern) for admin_pattern in admin_patterns):
                                            # If a superuser role matches the admin pattern, mark as Failed
                                            result = "Failed"

                                    # Step 3: Identify unprivileged roles with superuser privileges
                                    cursor.execute(""" 
                                                              WITH RECURSIVE roletree AS (
                                                                  SELECT u.rolname AS rolname,
                                                                         u.oid AS roloid,
                                                                         u.rolcanlogin,
                                                                         u.rolsuper,
                                                                         '{}'::name[] AS rolparents,
                                                                         NULL::oid AS parent_roloid,
                                                                         NULL::name AS parent_rolname
                                                                  FROM pg_catalog.pg_authid u
                                                                  LEFT JOIN pg_catalog.pg_auth_members m ON u.oid = m.member
                                                                  LEFT JOIN pg_catalog.pg_authid g ON m.roleid = g.oid
                                                                  WHERE g.oid IS NULL
                                                                  UNION ALL
                                                                  SELECT u.rolname AS rolname,
                                                                         u.oid AS roloid,
                                                                         u.rolcanlogin,
                                                                         u.rolsuper,
                                                                         t.rolparents || g.rolname AS rolparents,
                                                                         g.oid AS parent_roloid,
                                                                         g.rolname AS parent_rolname
                                                                  FROM pg_catalog.pg_authid u
                                                                  JOIN pg_catalog.pg_auth_members m ON u.oid = m.member
                                                                  JOIN pg_catalog.pg_authid g ON m.roleid = g.oid
                                                                  JOIN roletree t ON t.roloid = g.oid
                                                              )
                                                              SELECT
                                                                  ro.rolname,
                                                                  ro.roloid,
                                                                  ro.rolcanlogin,
                                                                  ro.rolsuper,
                                                                  ro.rolparents
                                                              FROM roletree ro
                                                              WHERE (ro.rolcanlogin AND ro.rolsuper)
                                                              OR
                                                              (
                                                                  ro.rolcanlogin AND EXISTS
                                                                  (
                                                                      SELECT TRUE FROM roletree ri
                                                                      WHERE ri.rolname = ANY (ro.rolparents)
                                                                      AND ri.rolsuper
                                                                  )
                                                              );
                                                          """)
                                    unprivileged_roles = cursor.fetchall()

                                    for role in unprivileged_roles:
                                        if any(role[0].startswith(admin_pattern) or role[0].endswith(admin_pattern) for admin_pattern in admin_patterns):
                                            # If unprivileged roles with superuser privileges found, mark as Failed
                                            result = "Failed"

                                    # Final result writing
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                              <td>4.6 Ensure the set_user extension is installed (Automated)</td>
                                                                              <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        # Write the note
                                        f.write(f'''<td><b>Note:</b> Check the admin users in our organization to ensure accurate identification of superuser roles.</td>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                              <td>4.6 Ensure the set_user extension is installed (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        # Write the note
                                        f.write(f'''<td><b>Note:</b> Check the admin users in our organization to ensure accurate identification of superuser roles. </td>''')
                                        Passed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                        <td>4.6 Ensure the set_user extension is installed (Automated)</td>
                                                                        <td class="status-nopermission">No Permission</td>
                                                                    </tr>''')
                                    # Write the note
                                    f.write(f'''<td><b>Note:</b> Check the admin users in our organization to ensure accurate identification of superuser roles.</td>''')
                                    NoPermission += 1

                                # 4.7 Make use of predefined roles (Manual)
                                f.write('''<tr>
                                                                      <td>4.7 Make use of predefined roles (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual += 1

                                # Close the table
                                f.write("</table>")

                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                  <strong>5. Connection and Login</strong>  
                                                                 </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                      <tr>
                                                                          <th>Check</th>
                                                                          <th>Status</th>
                                                                      </tr>''')

                                # 5.1 Ensure login via "local" UNIX Domain Socket is configured correctly (Manual)
                                f.write('''<tr>
                                                                      <td>5.1 Ensure login via "local" UNIX Domain Socket is configured correctly (Manual)</td>
                                                                      <td class="status-manual">No Need</td>
                                                               </tr>''')


                                # 5.2 Ensure login via "host" TCP/IP Socket is configured correctly (Manual)
                                f.write('''<tr>
                                                                      <td>5.2 Ensure login via "host" TCP/IP Socket is configured correctly (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual += 1

                                """1. Check for password assignment for the postgres role:
                                Sql
                                ALTER ROLE postgres WITH PASSWORD 'secret_password';

                                2. Test an unencrypted session (using sslmode=disable): Open a command prompt and test the unencrypted session:
                                bash psql "host=localhost user=postgres sslmode=disable"
                                You should be prompted for a password.

                                3. Test an encrypted session (using sslmode=require):
                                bash psql "host=localhost user=postgres sslmode=require"
                                You should be prompted for a password, ensuring that encryption is enforced.

                                4. Remote login tests: For remote hosts, replace localhost with the actual server name or IP address 
                                in the connection string:

                                Test unencrypted session from a remote host:
                                bash psql "host=server-name-or-IP user=postgres sslmode=disable"
                                You should be prompted for the password.

                                Test encrypted session from a remote host:
                                bash psql "host=server-name-or-IP user=postgres sslmode=require"
                                You should be prompted for the password, confirming encryption is enabled."""

                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Step 1: Check the value of shared_preload_libraries
                                    cursor.execute("SHOW shared_preload_libraries;")
                                    shared_preload_libraries = cursor.fetchone()

                                    # Step 2: Check the value of dynamic_library_path
                                    cursor.execute("SHOW dynamic_library_path;")
                                    dynamic_library_path = cursor.fetchone()

                                    # Check if '$libdir/passwordcheck' is part of the shared_preload_libraries string and if '$libdir' is in dynamic_library_path
                                    if '$libdir/passwordcheck' not in shared_preload_libraries[0] and '$libdir' in \
                                            dynamic_library_path[0]:
                                        result = "Failed"

                                    # Final result writing
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                              <td>5.3 Ensure Password Complexity is configured (Manual)</td>
                                                                              <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                              <td>5.3 Ensure Password Complexity is configured (Manual)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                        <td>5.3 Ensure Password Complexity is configured (Manual)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')
                                    NoPermission += 1

                                # Close the table
                                f.write("</table>")

                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                                                                  <strong>6. PostgreSQL Settings</strong>  
                                                                                                 </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                        <tr>
                                                                            <th>Check</th>
                                                                            <th>Status</th>
                                                                        </tr>''')

                                # 6.1 Understanding attack vectors and runtime parameters (Manual)
                                f.write('''<tr>
                                                                      <td>6.1 Understanding attack vectors and runtime parameters (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual +=1

                                # 6.2 Ensure 'backend' runtime parameters are configured correctly (Automated)

                                """This command lists key parameters relevant to backend and superuser-backend contexts. 
                                   Typical expected settings include:
                                   ignore_system_indexes: off — Ensures system indexes are used, improving query performance.
                                   jit_debugging_support: off — Disables JIT debugging, which is typically unnecessary and could expose debugging data.
                                   jit_profiling_support: off — Disables JIT profiling, reducing performance overhead.
                                   log_connections: on — Logs each connection, aiding in audit trails.
                                   log_disconnections: on — Logs each disconnection, also aiding in audit trails.
                                   post_auth_delay: 0 — No delay after authentication, reducing overhead."""
                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Define the expected settings for backend parameters
                                    expected_settings = {
                                        "ignore_system_indexes": "off",
                                        "jit_debugging_support": "off",
                                        "jit_profiling_support": "off",
                                        "log_connections": "on",
                                        "log_disconnections": "on",
                                        "post_auth_delay": "0"
                                    }

                                    # Query to fetch backend and superuser-backend parameters
                                    cursor.execute("SELECT name, setting FROM pg_settings WHERE context IN ('backend', 'superuser-backend') ORDER BY name;")
                                    backend_params = cursor.fetchall()

                                    # Check each parameter against the expected settings
                                    for param, value in backend_params:
                                        if param in expected_settings and value != expected_settings[param]:
                                            # If a parameter does not match the expected setting, mark as Failed
                                            result = "Failed"
                                            break

                                    # Final result writing
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                              <td>6.2 Ensure 'backend' runtime parameters are configured correctly (Automated)</td>
                                                                              <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                    else:
                                        f.write('''<tr>
                                                                              <td>6.2 Ensure 'backend' runtime parameters are configured correctly (Automated)</td>
                                                                              <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                        <td>6.2 Ensure 'backend' runtime parameters are configured correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')

                                    NoPermission += 1

                                # Check the expected configuration for 'postmaster' runtime parameters
                                """expected_settings = {
                                    "archive_mode": "off",
                                    "autovacuum_freeze_max_age": "200000000",
                                    "autovacuum_max_workers": "3",
                                    "autovacuum_multixact_freeze_max_age": "400000000",
                                    "bonjour": "off",
                                    "bonjour_name": "",
                                    "cluster_name": "",
                                    "config_file": "C:/Program Files/PostgreSQL/16/data/postgresql.conf",

                                    # Adjusted for Windows paths
                                    "data_directory": "C:/Program Files/PostgreSQL/16/data",
                                    # Adjusted for Windows paths
                                    "data_sync_retry": "off",
                                    "debug_io_direct": "",
                                    "dynamic_shared_memory_type": "posix",
                                    "event_source": "PostgreSQL",
                                    "external_pid_file": "",
                                    "hba_file": "C:/Program Files/PostgreSQL/16/data/pg_hba.conf",
                                    # Adjusted for Windows paths
                                    "hot_standby": "on",
                                    "huge_pages": "try",
                                    "huge_page_size": "0",
                                    "ident_file": "C:/Program Files/PostgreSQL/16/data/pg_ident.conf",
                                    # Adjusted for Windows paths
                                    "ignore_invalid_pages": "off",
                                    "jit_provider": "llvmjit",
                                    "listen_addresses": "localhost",  # Adjusted for typical use
                                    "logging_collector": "on",
                                    "max_connections": "100",
                                    "max_files_per_process": "1000",
                                    "max_locks_per_transaction": "64",
                                    "max_logical_replication_workers": "4",
                                    "max_pred_locks_per_transaction": "64",
                                    "max_prepared_transactions": "0",
                                    "max_replication_slots": "10",
                                    "max_wal_senders": "10",
                                    "max_worker_processes": "8",
                                    "min_dynamic_shared_memory": "0",
                                    "old_snapshot_threshold": "-1",
                                    "port": "5432",
                                    "recovery_target": "",
                                    "recovery_target_action": "pause",
                                    "recovery_target_inclusive": "on",
                                    "recovery_target_lsn": "",
                                    "recovery_target_name": "",
                                    "recovery_target_time": "",
                                    "recovery_target_timeline": "latest",
                                    "recovery_target_xid": "",
                                    "reserved_connections": "0",
                                    "shared_buffers": "16384",
                                    "shared_memory_type": "windows",  # Adjusted for Windows environment
                                    "shared_preload_libraries": "set_user,pgaudit",
                                    "superuser_reserved_connections": "3",
                                    "track_activity_query_size": "1024",
                                    "track_commit_timestamp": "off",
                                    "unix_socket_directories": "C:/Program Files/PostgreSQL/16/tmp",
                                    # Adjusted for Windows paths
                                    "unix_socket_group": "",
                                    "unix_socket_permissions": "0777",
                                    "wal_buffers": "512",
                                    "wal_decode_buffer_size": "524288",
                                    "wal_level": "replica",
                                    "wal_log_hints": "off"
                                }"""

                                # 6.3 Ensure 'Postmaster' runtime parameters are configured correctly (Manual)
                                f.write('''<tr>
                                                                      <td>6.3 Ensure 'Postmaster' runtime parameters are configured correctly (Manual)</td>
                                                                       <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual +=1

                                # 6.4 Ensure 'SIGHUP' Runtime Parameters are Configured (Manual)

                                f.write('''<tr>
                                                                      <td>6.4 Ensure 'SIGHUP' Runtime Parameters are Configured (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                               </tr>''')
                                Manual += 1

                                # 6.5 Ensure 'Superuser' Runtime Parameters are Configured (Manual)

                                f.write('''<tr>
                                                                     <td>6.5 Ensure 'Superuser' Runtime Parameters are Configured (Manual)</td>
                                                                     <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual += 1

                                # 6.6 Ensure 'User' Runtime Parameters are Configured (Manual)

                                f.write('''<tr>
                                                                      <td>6.6 Ensure 'User' Runtime Parameters are Configured (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                               </tr>''')
                                Manual += 1

                                # 6.7 Ensure FIPS 140-2 OpenSSL Cryptography Is Used (Automated)
                                # Combined FIPS and OpenSSL compliance check

                                """
                                Verify with .NET as a Confirmation Step 
                                Another check for FIPS compliance can be done using .NET libraries directly in PowerShell:
                                [System.Security.Cryptography.CryptoConfig]::AllowOnlyFipsAlgorithms
                                This command should return True if FIPS mode is enforced."""

                                """Check if OpenSSL is Installed on Windows
                                   win + r in cmd: openssl version"""

                                """
                                FIPS Compliance Check: It uses .NET's CryptoConfig.AllowOnlyFipsAlgorithms to verify if FIPS mode is enabled.
                                OpenSSL Compliance Check: Runs openssl version via a subprocess, checking if the version output contains "OpenSSL 3.0" 
                                (indicating compliance).

                                Result Handling:
                                If both FIPS and OpenSSL checks pass, result remains "Passed."
                                If either check fails, result is set to "Failed."
                                If an exception occurs (e.g., permissions issue), result is set to "NoPermission."
                                """
                                # 6.7 Ensure FIPS 140-2 OpenSSL Cryptography Is Used (Automated)
                                f.write('''<tr>
                                                                      <td>6.7 Ensure FIPS 140-2 OpenSSL Cryptography Is Used (Automated)</td>
                                                                      <td class="status-nopermission">No Permission</td>
                                                                  </tr>''')
                                # Write the note
                                f.write(
                                    f'''<td><b>Note:</b> Only system administrator has the permission</td>''')
                                NoPermission += 1

                                # 6.8 Ensure TLS is enabled and configured correctly (Automated)

                                """This command checks the ssl configuration to ensure that TLS is enabled in PostgreSQL.
                                   Expected setting: ssl = on — Ensures that TLS is used for encrypted connections."""

                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Query to fetch the SSL setting
                                    cursor.execute("SELECT name, setting FROM pg_settings WHERE name = 'ssl';")
                                    ssl_param = cursor.fetchone()

                                    # Check if TLS (ssl) is enabled
                                    if ssl_param:
                                        name, setting = ssl_param
                                        if setting != 'on':
                                            # If ssl is off, mark as Failed
                                            result = "Failed"
                                    else:
                                        # If ssl parameter is not found, mark as Failed
                                        result = "Failed"

                                    # Final result writing to HTML report
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                            <td>6.8 Ensure TLS is enabled and configured correctly (Automated)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                          </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                            <td>6.8 Ensure TLS is enabled and configured correctly (Automated)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                          </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    # If an exception occurs (e.g., permission issue or query failure), mark as NoPermission
                                    f.write('''<tr>
                                                                        <td>6.8 Ensure TLS is enabled and configured correctly (Automated)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                      </tr>''')
                                    NoPermission += 1

                                # Close the table
                                f.write("</table>")

                                # 7. Replication
                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                  <strong> 7. Replication</strong>  
                                                                 </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                        <tr>
                                                                            <th>Check</th>
                                                                            <th>Status</th>
                                                                        </tr>''')

                                # 7.1 Ensure a replication-only user is created and used for streaming replication (Manual)

                                """Purpose: This audit checks if a dedicated user has been created for streaming replication, 
                                   instead of using the superuser (postgres) account. 
                                   Using a separate replication-only user is a security best practice, 
                                   as it limits the privileges of the user responsible for replication."""

                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Query to find users with replication permissions
                                    cursor.execute("SELECT rolname FROM pg_roles WHERE rolreplication = true;")
                                    replication_users = cursor.fetchall()

                                    # Check if there is only the 'postgres' user with replication permissions
                                    if len(replication_users) == 1 and replication_users[0][0] == "postgres":
                                        result = "Failed"  # Only postgres has replication permission, not compliant

                                    # Final result writing to HTML report
                                    if result == "Failed":

                                        """Non-Compliant (Failed): If only the postgres user has replication permissions, it means the system is
                                           using the superuser for replication. This violates the principle of least privilege and the requirement 
                                           to create a dedicated replication user."""

                                        f.write('''<tr>
                                                                            <td>7.1 Ensure a replication-only user is created and used for streaming replication (Manual)</td>
                                                                            <td class="status-failed">Failed</td>
                                                                          </tr>''')
                                        Failed += 1
                                    else:

                                        """Compliant (Passed): If there are additional users (other than postgres) with replication permissions,
                                         it indicates that a separate replication user has been created. This satisfies the requirement."""

                                        f.write('''<tr>
                                                                            <td>7.1 Ensure a replication-only user is created and used for streaming replication (Manual)</td>
                                                                            <td class="status-passed">Passed</td>
                                                                          </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    # If an exception occurs (e.g., permission issue or query failure), mark as NoPermission
                                    f.write('''<tr>
                                                                        <td>7.1 Ensure a replication-only user is created and used for streaming replication (Manual)</td>
                                                                        <td class="status-nopermission">NoPermission</td>
                                                                      </tr>''')
                                    NoPermission += 1

                                # 7.2 Ensure logging of replication commands is configured (Manual)

                                """This command checks the current value of the 'log_replication_commands' setting.
                                   If set to 'on', replication commands will be logged. This is crucial for security and auditing replication activities."""

                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Query to check the current value of log_replication_commands
                                    cursor.execute("SHOW log_replication_commands;")
                                    replication_logging_setting = cursor.fetchone()

                                    # If log_replication_commands is not 'on', mark as Failed
                                    if replication_logging_setting and replication_logging_setting[0] != "on":
                                        result = "Failed"

                                    # Final result writing to HTML report
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                          <td>7.2 Ensure logging of replication commands is configured (Manual)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                      </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                          <td>7.2 Ensure logging of replication commands is configured (Manual)</td>
                                                                          <td class="status-passed">Passed</td>
                                                                      </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                     <td>7.2 Ensure logging of replication commands is configured (Manual)</td>
                                                                     <td class="status-nopermission">NoPermission</td>
                                                                 </tr>''')
                                    NoPermission += 1

                                # 7.3 Ensure base backups are configured and functional (Manual)
                                f.write('''<tr>
                                                                     <td>7.3 Ensure base backups are configured and functional (Manual)</td>
                                                                     <td class="status-manual">Manual</td>
                                                                </tr>''')
                                Manual += 1

                                # 7.4 Ensure WAL archiving is configured and functional (Automated)

                                """This command checks the necessary parameters to ensure that WAL archiving is enabled and functional. 
                                   If 'archive_mode' is 'on' and either 'archive_command' or 'archive_library' is set, the configuration is correct."""

                                try:
                                    # Initialize the result variable
                                    result = "Passed"

                                    # Query to check archive-related parameters
                                    cursor.execute(
                                        "SELECT name, setting FROM pg_settings WHERE name ~ '^archive' ORDER BY 1;")
                                    archive_params = cursor.fetchall()

                                    # Flags to check the parameters
                                    archive_mode = False
                                    archive_command_enabled = False
                                    archive_library_enabled = False

                                    for param, value in archive_params:
                                        if param == "archive_mode" and value == "on":
                                            archive_mode = True
                                        elif param == "archive_command" and value == "(enabled)":
                                            archive_command_enabled = True
                                        elif param == "archive_library" and value == "(enabled)":
                                            archive_library_enabled = True

                                    # If archive_mode is off or either archive_command or archive_library is not enabled, mark as Failed
                                    if not archive_mode or not (archive_command_enabled and archive_library_enabled):
                                        result = "Failed"

                                    # Final result writing to HTML report
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                          <td>7.4 Ensure WAL archiving is configured and functional (Automated)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                      </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                          <td>7.4 Ensure WAL archiving is configured and functional (Automated)</td>
                                                                          <td class="status-passed">Passed</td>
                                                                      </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    f.write('''<tr>
                                                                     <td>7.4 Ensure WAL archiving is configured and functional (Automated)</td>
                                                                     <td class="status-nopermission">NoPermission</td>
                                                                 </tr>''')
                                    NoPermission += 1

                                #7.5 Ensure streaming replication parameters are configured correctly (Manual)
                                f.write('''<tr>
                                                                      <td>7.5 Ensure streaming replication parameters are configured correctly (Manual)</td>
                                                                      <td class="status-manual">Manual</td>
                                                                  </tr>''')
                                Manual += 1

                                # Close the table
                                f.write("</table>")

                                # 8 Special Configuration Considerations
                                f.write('''<p style="color: #00008B; font-size: 20px; text-align: left; margin-top: 20px;">
                                                                          <strong>8. Special Configuration Considerations</strong>  
                                                              </p>''')

                                # Start the table for the checks
                                f.write('''<table>
                                                                        <tr>
                                                                            <th>Check</th>
                                                                            <th>Status</th>
                                                                        </tr>''')
                                #8.1 Ensure PostgreSQL subdirectory locations are outside the data cluster (Manual)
                                try:
                                    # Initialize the result as "Passed"
                                    result = "Passed"

                                    # Query to fetch the required directory and tablespace settings
                                    cursor.execute("SELECT name, setting FROM pg_settings WHERE (name ~ '_directory$' OR name ~ '_tablespace' OR name = 'allow_in_place_tablespaces' OR name = 'temp_file_limit')")
                                    settings = cursor.fetchall()

                                    # Initialize flags based on criteria
                                    log_directory_correct = False
                                    temp_tablespaces_defined_or_temp_file_limit_set = False
                                    data_directory_correct = False
                                    allow_in_place_tablespaces_off = False

                                    # Check each setting based on the criteria
                                    for param, value in settings:
                                        if param == "log_directory" and value == "log":
                                            log_directory_correct = True
                                        elif param == "temp_tablespaces":
                                            # temp_tablespaces can be empty, so we check if temp_file_limit is set if temp_tablespaces is empty
                                            if value:
                                                temp_tablespaces_defined_or_temp_file_limit_set = True
                                        elif param == "data_directory" and value == "C:/Program Files/PostgreSQL/16/data":
                                            data_directory_correct = True
                                        elif param == "allow_in_place_tablespaces" and value == "off":
                                            allow_in_place_tablespaces_off = True
                                        elif param == "temp_file_limit" and int(value) != 0:
                                            temp_tablespaces_defined_or_temp_file_limit_set = True

                                    # Determine pass or fail based on all conditions
                                    if not (log_directory_correct and
                                            data_directory_correct and
                                            allow_in_place_tablespaces_off and
                                            temp_tablespaces_defined_or_temp_file_limit_set):
                                        result = "Failed"

                                    # Write the result to the HTML report
                                    if result == "Failed":
                                        f.write('''<tr>
                                                                          <td>8.1 Ensure PostgreSQL subdirectory locations are outside the data cluster (Manual)</td>
                                                                          <td class="status-failed">Failed</td>
                                                                        </tr>''')
                                        Failed += 1
                                    else:
                                        f.write('''<tr>
                                                                          <td>8.1 Ensure PostgreSQL subdirectory locations are outside the data cluster (Manual)</td>
                                                                          <td class="status-passed">Passed</td>
                                                                        </tr>''')
                                        Passed += 1

                                except Exception as e:
                                    # Handle exceptions by logging as NoPermission
                                    f.write('''<tr>
                                                                      <td>8.1 Ensure PostgreSQL subdirectory locations are outside the data cluster (Manual)</td>
                                                                      <td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')
                                    NoPermission += 1


                                # 8.2 Ensure the backup and restore tool, 'pgBackRest', is installed and configured (Automated)
                                f.write('''<tr>
                                                                      <td>8.2 Ensure the backup and restore tool, 'pgBackRest', is installed and configured (Automated)</td>
                                                                      <<td class="status-nopermission">NoPermission</td>
                                                                    </tr>''')
                                NoPermission += 1

                                """To ensure that your organization implements an effective backup solution for PostgreSQL databases, 
                                similar to pgBackRest's features """

                                # Write the note with the actual log_timezone value
                                f.write('''<td><b>Note:</b> To ensure that your organization implements an effective backup solution for PostgreSQL databases, 
                                                      similar to pgBackRest's features''')

                                # Close the table
                                f.write("</table>")

                                # Open the table after all rows are written
                                f.write('''<table class="summary-table" style="width: 100%; margin-top: 20px; border-collapse: collapse;">
                                                                                              <tr>
                                                                                                  <th>Total Passed</th>
                                                                                                  <th>Total Failed</th>
                                                                                                  <th>Total Manual</th>
                                                                                                  <th>No Permission</th>
                                                                                              </tr>
                                                                                              <tr>
                                                                                                  <td class="status-passed" style="text-align: center;">{}</td>
                                                                                                  <td class="status-failed" style="text-align: center;">{}</td>
                                                                                                  <td class="status-manual" style="text-align: center;">{}</td>
                                                                                                  <td class="status-nopermission" style="text-align: center;">{}</td>
                                                                                              </tr>
                                                                                            </table>
                                                                                                <footer style="text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0;">
                                                                                                    <p>2024 All Rights Reserved to Secure Auditix tool</p>
                                                                                                    <p>Coded and UI Designed by <strong>Mandavalli Ganesh<strong></p>
                                                                                                </footer>
                                                                                         </body>
                                                                                     </html>'''.format(Passed, Failed, Manual, NoPermission,
                                                                                                       Passed, Failed, Manual,
                                                                                                       NoPermission))
                        except Exception as e:
                            print(f"Error saving the report: {e}")
                        finally:
                            # Close the cursor and connection
                            if cursor:
                                cursor.close()
                            if connection:
                                connection.close()

                                # Return the HTML file as a downloadable attachment
                                with open(file_path, 'r') as file:
                                    response = HttpResponse(file.read(), content_type='text/html')
                                    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                                    return response

                    else:

                        # Assuming 'selected_standard', 'server', 'database', 'username', and 'password' are provided from user input

                        if selected_standard == "DISA_STIG":

                            server_parts = server.split(",")

                            if len(server_parts) != 2:
                                message = "Please specify both host and port as host,port."

                                return

                            host = server_parts[0]

                            port = server_parts[1]

                            try:


                                # Connect to PostgreSQL with specified host and port

                                connection = psycopg2.connect(

                                    host=host,

                                    port=port,

                                    dbname=database,

                                    user=username,

                                    password=password

                                )

                                # Create a cursor and execute a query

                                cursor = connection.cursor()

                                # Get the current datetime for the report header

                                current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                                # Path to save the HTML file in the Downloads directory

                                # Define file path inside Django's media directory
                                file_name = "Postgres_SQL_results.htm"
                                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                                # Ensure MEDIA_ROOT exists
                                os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

                                # Open the file for writing (HTML structure)

                                with open(file_path, "w") as f:

                                    # Write the initial HTML structure

                                    f.write(f"""<html lang="en">

                                    <head>

                                       <meta charset="UTF-8">

                                       <meta name="viewport" content="width=device-width, initial-scale=1.0">

                                       <title>Audit Report</title>

                                       <style>

                                          body {{ font-family: Arial, sans-serif; margin: 20px; }}

                                          .header {{ text-align: right; font-size: 14px; margin-bottom: 10px; }}

                                          .info-box {{ background-color: #f2f2f2; padding: 15px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }}

                                          h2 {{ color: #00008B; text-align: center; margin-top: 20px; }}

                                          h3 {{ color: #00008B; text-align: left; margin-top: 20px; }}

                                          table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}

                                          table, th, td {{ border: 1px solid #ddd; }}

                                          th, td {{ padding: 12px; text-align: left; }}

                                          th {{ background-color: #00008B; color: white; }}

                                          tr:nth-child(even) {{ background-color: #f2f2f2; }}

                                          .status-passed {{ color: green; }}

                                          .status-failed {{ color: red; }}

                                          .status-manual {{ color: black; }}

                                          .status-nopermission {{ color: yellow; }}

                                          .footer {{ text-align: center; font-size: 14px; margin-top: 30px; padding: 10px 0; }}

                                       </style>

                                    </head>

                                    <body>

                                        <div class="header"><strong>Audit Date: </strong>{current_datetime}</div>

                                    """)

                                    # Execute the query to fetch PostgreSQL version

                                    cursor.execute("SELECT version();")

                                    print("Executed SELECT version(); query.")

                                    # Fetch the result

                                    version_info = cursor.fetchall()

                                    print("Fetched version info:", version_info)

                                    # Loop through the result and write it into the HTML file

                                    for row in version_info:
                                        f.write(f'''<div class="info-box">

                                        <p><strong>{row[0]}</strong><br> </p> 

                                        </div>''')

                                        # Add a horizontal line for separation

                                        f.write("<hr style='border: 1px solid #00008B; margin: 20px 0;'>\n")

                                        # Write the additional messages in paragraph tags

                                        f.write(
                                            "<p style='font-weight: bold; color: #00008B;'>Database Auditing - DISA STIG is coming soon...</p>\n")

                                        f.write(
                                            "<p>Currently under maintenance, Update is coming in next release.</p>\n")

                                        f.write("<p>Thank you - Please Visit again.</p>\n")


                            except Exception as e:

                                # Handle errors during database connection or execution

                                print(f"Error: {e}")

                            finally:

                                # Close the cursor and connection

                                if 'cursor' in locals() and cursor:
                                    cursor.close()

                                if 'connection' in locals() and connection:
                                    connection.close()

                                    # Return the HTML file as a downloadable attachment
                                    with open(file_path, 'r') as file:
                                        response = HttpResponse(file.read(), content_type='text/html')
                                        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                                        return response

                except (psycopg2.OperationalError) as e:
                    return JsonResponse({"error": f"Database Error: {str(e)}"}, status=500)

        except (psycopg2.OperationalError, cx_Oracle.DatabaseError, pyodbc.Error) as e:
            return JsonResponse({"error": f"Database Error: {str(e)}"}, status=500)
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'connection' in locals():
                connection.close()

        return JsonResponse({"error": "Invalid request method."}, status=405)