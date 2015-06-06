//
// VMime library (http://www.vmime.org)
// Copyright (C) 2002-2013 Vincent Richard <vincent@vmime.org>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Linking this library statically or dynamically with other modules is making
// a combined work based on this library.  Thus, the terms and conditions of
// the GNU General Public License cover the whole combination.
//

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <locale>
#include <clocale>
#include <string>

#include <regex>	

#include <vmime/vmime.hpp>
#include <vmime/platforms/posix/posixHandler.hpp>

#include <curl/curl.h>

#include "example6_tracer.hpp"
#include "example6_authenticator.hpp"
#include "example6_certificateVerifier.hpp"
#include "example6_timeoutHandler.hpp"


// Global session object
static vmime::shared_ptr <vmime::net::session> g_session
	= vmime::make_shared <vmime::net::session>();


// callback function writes data to a std::ostream
static size_t data_write(void* buf, size_t size, size_t nmemb, void* userp)
{
	if(userp)
	{
		std::ostream& os = *static_cast<std::ostream*>(userp);
		std::streamsize len = size * nmemb;
		if(os.write(static_cast<char*>(buf), len))
			return len;
	}

	return 0;
}

/**
 * timeout is in seconds
 **/
CURLcode curl_read(std::string url, std::ostream& os, long timeout = 60)
{
	CURLcode code(CURLE_FAILED_INIT);
	CURL* curl = curl_easy_init();

	if(curl)
	{
		if(CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &data_write))
		&& CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L))
		&& CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L))
		&& CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_FILE, &os))
		&& CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout))
		&& CURLE_OK == (code = curl_easy_setopt(curl, CURLOPT_URL, url.c_str())))
		{
			code = curl_easy_perform(curl);
		}
		curl_easy_cleanup(curl);
	}
	return code;
}

std::vector <std::string> regexFind(std::string data, std::string regex){
  std::string s = data;
  std::smatch m;
  std::regex e (regex);   // matches words beginning by "sub"

  std::vector <std::string> matches;
  while (std::regex_search (s,m,e)) {
    for (auto x:m) matches.push_back(x);
    s = m.suffix().str();
  }
  return matches;
}

std::vector <std::string> googleImages(std::string query){
	curl_global_init(CURL_GLOBAL_ALL);

	std::ostringstream oss;
	std::string html;
	std::regex space ("( )");

	std::string request ("http://ajax.googleapis.com/ajax/services/search/images?v=1.0&q=" + query);
	request = request.substr(0, (request.size()-2));

	request = std::regex_replace(request, space, "%20");
	
	if(CURLE_OK == curl_read(request, oss))
	{
		// Web page successfully written to string
		html = oss.str();
	}

	std::vector <std::string> matches = regexFind(html, "http://[a-z0-9A-Z/._\\(\\)-]*\\.(?:gif|png|jpg)");

	curl_global_cleanup();	
 	return matches;
}


/** Returns the messaging protocols supported by VMime.
  *
  * @param type service type (vmime::net::service::TYPE_STORE or
  * vmime::net::service::TYPE_TRANSPORT)
  */
static const std::string findAvailableProtocols(const vmime::net::service::Type type)
{
	vmime::shared_ptr <vmime::net::serviceFactory> sf =
		vmime::net::serviceFactory::getInstance();

	std::ostringstream res;
	int count = 0;

	for (int i = 0 ; i < sf->getServiceCount() ; ++i)
	{
		const vmime::net::serviceFactory::registeredService& serv = *sf->getServiceAt(i);

		if (serv.getType() == type)
		{
			if (count != 0)
				res << ", ";

			res << serv.getName();
			++count;
		}
	}

	return res.str();
}



// Exception helper
static std::ostream& operator<<(std::ostream& os, const vmime::exception& e)
{
	os << "* vmime::exceptions::" << e.name() << std::endl;
	os << "    what = " << e.what() << std::endl;

	// More information for special exceptions
	if (dynamic_cast <const vmime::exceptions::command_error*>(&e))
	{
		const vmime::exceptions::command_error& cee =
			dynamic_cast <const vmime::exceptions::command_error&>(e);

		os << "    command = " << cee.command() << std::endl;
		os << "    response = " << cee.response() << std::endl;
	}

	if (dynamic_cast <const vmime::exceptions::invalid_response*>(&e))
	{
		const vmime::exceptions::invalid_response& ir =
			dynamic_cast <const vmime::exceptions::invalid_response&>(e);

		os << "    response = " << ir.response() << std::endl;
	}

	if (dynamic_cast <const vmime::exceptions::connection_greeting_error*>(&e))
	{
		const vmime::exceptions::connection_greeting_error& cgee =
			dynamic_cast <const vmime::exceptions::connection_greeting_error&>(e);

		os << "    response = " << cgee.response() << std::endl;
	}

	if (dynamic_cast <const vmime::exceptions::authentication_error*>(&e))
	{
		const vmime::exceptions::authentication_error& aee =
			dynamic_cast <const vmime::exceptions::authentication_error&>(e);

		os << "    response = " << aee.response() << std::endl;
	}

	if (dynamic_cast <const vmime::exceptions::filesystem_exception*>(&e))
	{
		const vmime::exceptions::filesystem_exception& fse =
			dynamic_cast <const vmime::exceptions::filesystem_exception&>(e);

		os << "    path = " << vmime::platform::getHandler()->
			getFileSystemFactory()->pathToString(fse.path()) << std::endl;
	}

	if (e.other() != NULL)
		os << *e.other();

	return os;
}


/** Send a message interactively.
  */
static void sendMessage(std::string recipient, std::string message, std::string subject)
{
	try
	{
		
		// std::cout << "Time to do some automation" << std::endl;

		//std::getline(std::cin, urlString);

		vmime::utility::url url("<REMOVED FOR SECURITY>");
		

		vmime::shared_ptr <vmime::net::transport> tr = g_session->getTransport(url);
		// // std::cout << "username: " << url.getUsername() << " host" << url.getHost() << " pass" << url.getPassword() <<  " " << url.getPath() << " " << url.getPort() << std::endl;
		

		tr->setProperty("options.sasl", true);
		tr->setProperty("connection.tls", true);
		tr->setProperty("auth.username", "<REMOVED FOR SECURITY>");
		tr->setProperty("auth.password", "<REM<OVED FOR SECURITY>");
		

		tr->setProperty("options.need-authentication", true);
		
		// // std::cout << "just after TLS is set "<<std::endl;
		// Trace communication between client and server
		tr->setTimeoutHandlerFactory(vmime::make_shared <timeoutHandlerFactory>());
		tr->setCertificateVerifier(vmime::make_shared <interactiveCertificateVerifier>());
		


		vmime::shared_ptr <std::ostringstream> traceStream = vmime::make_shared <std::ostringstream>();
		tr->setTracerFactory(vmime::make_shared <myTracerFactory>(traceStream));


		// // Information about the mail

		vmime::mailbox from("<REMOVED FOR SECURITY>");
		vmime::mailboxList to;

		vmime::string toString = recipient;
		to.appendMailbox(vmime::make_shared <vmime::mailbox>(toString));

		
		const vmime::datetime date = vmime::datetime::now();
		vmime::string dateStr;
		vmime::utility::outputStreamStringAdapter outStr(dateStr);
		date.generate(outStr);

		std::ostringstream data;

		data << "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:31.0) Gecko/20100101 Thunderbird/31.7.0\r\n"
			 << "MIME-Version: 1.0\r\n"
			 << "Content-Type: text/html; charset=utf-8\r\n"
			 << "Content-Transfer-Encoding: 7bit\r\n"
			 << "Content-Disposition: inline\r\n"
			 << "Date: " << dateStr << "\r\n"
			 << "To: " << recipient << "\r\n"
			 << "From: test <snafu@mewy.pw>\r\n"
			 << "Subject: " << subject << "\r\n"
			 << "<!DOCTYPE html>\r\n"
			 << "<html><body>\r\n"
			 << message << "\r\n"
			 << "</body></html>\r\n"
			 << "awesome message";

		// std::cout << "just after data is set "<<std::endl;
		// Connect to server
		tr->connect();

		// Send the message
		vmime::string msgData = data.str();
		vmime::utility::inputStreamStringAdapter vis(msgData);

		tr->send(from, to, vis, msgData.length());

		// Note: you could also write this:
		//     vmime::message msg;
		//     ...
		//     tr->send(&msg);

		// Display connection log
		// std::cout << std::endl;
		// std::cout << "Connection Trace:" << std::endl;
		// std::cout << "=================" << std::endl;
		// std::cout << traceStream->str();

		tr->disconnect();
	}
	catch (vmime::exception& e)
	{
		std::cerr << std::endl;
		std::cerr << e << std::endl;
		throw;
	}
	catch (std::exception& e)
	{
		std::cerr << std::endl;
		std::cerr << "std::exception: " << e.what() << std::endl;
		throw;
	}
}


/** Connect to a message store interactively.
  */
static void connectStore()
{
	try
	{
		// Request user to enter an URL
		// std::cout << "Enter an URL to connect to store service." << std::endl;
		// std::cout << "Available protocols: " << findAvailableProtocols(vmime::net::service::TYPE_STORE) << std::endl;
		// std::cout << "(eg. pop3://user:pass@myserver.com, imap://myserver.com:123)" << std::endl;
		// std::cout << "> ";
		// // std::cout.flush();

		vmime::string urlString;
		// std::getline(std::cin, urlString);

		// vmime::utility::url url(urlString);
		vmime::utility::url url("<REMOVED FOR SECURITY>");
		// std::cout << "after utility URL" << std::endl;
		
		url.setUsername("<REMOVED FOR SECURITY>");
		url.setPassword("<REMOVED FOR SECURITY>");

		// If no authenticator is given in argument to getStore(), a default one
		// is used. Its behaviour is to get the user credentials from the
		// session properties "auth.username" and "auth.password".
		vmime::shared_ptr <vmime::net::store> st = g_session->getStore(url);

		
		// std::cout << "after setting auth URL" << std::endl;
#if VMIME_HAVE_TLS_SUPPORT

		// Enable TLS support if available
		st->setProperty("connection.tls", true);

		// Set the time out handler
		st->setTimeoutHandlerFactory(vmime::make_shared <timeoutHandlerFactory>());

		// Set the object responsible for verifying certificates, in the
		// case a secured connection is used (TLS/SSL)
		st->setCertificateVerifier
			(vmime::make_shared <interactiveCertificateVerifier>());

#endif // VMIME_HAVE_TLS_SUPPORT

		// std::cout << "after TLS" << std::endl;
		// Trace communication between client and server
		vmime::shared_ptr <std::ostringstream> traceStream = vmime::make_shared <std::ostringstream>();
		st->setTracerFactory(vmime::make_shared <myTracerFactory>(traceStream));


		// std::cout << "username: " << url.getUsername() << " host" << url.getHost() << " pass" << url.getPassword() <<  " " << url.getPath() << " " << url.getPort() << std::endl;
		// std::cout << "after just before connect" << std::endl;
		// Connect to the mail store
		st->connect();

		// std::cout << "after connection" << std::endl;
		// Display some information about the connection
		vmime::shared_ptr <vmime::net::connectionInfos> ci = st->getConnectionInfos();

		// std::cout << std::endl;
		// std::cout << "Connected to '" << ci->getHost() << "' (port " << ci->getPort() << ")" << std::endl;
		// std::cout << "Connection is " << (st->isSecuredConnection() ? "" : "NOT ") << "secured." << std::endl;

		// Open the default folder in this store
		// vmime::shared_ptr <vmime::net::folder> f = st->getDefaultFolder();
		vmime::shared_ptr <vmime::net::folder> f = st->getFolder(vmime::utility::path("INBOX"));

		f->open(vmime::net::folder::MODE_READ_WRITE);

		int count = f->getMessageCount();

		// std::cout << std::endl;
		// std::cout << count << " message(s) in your inbox" << std::endl;
/*
	need to do:
	while getMessageCount != 0
		scan the message for sender and subject line
		sendmessage(sender, googleapisubject)
		move message to archive

*/
		for (bool cont = true ; cont ; )
		{
			typedef std::map <int, vmime::shared_ptr <vmime::net::message> > MessageList;
			MessageList msgList;

			try
			{
				
				// Request message number
				vmime::shared_ptr <vmime::net::message> msg;

				for(int num = 1; num <= f->getMessageCount(); num++)
				{
					
					MessageList::iterator it = msgList.find(num);

					if (it != msgList.end())
					{
						msg = (*it).second;
					}
					else
					{
						msg = f->getMessage(num);
						msgList.insert(MessageList::value_type(num, msg));
					}

					f->fetchMessage(msg, vmime::net::fetchAttributes::FLAGS);

					if (msg->getFlags() & vmime::net::message::FLAG_DELETED){
						// std::cout << "FLAG_DELETED" << std::endl;
					} else {
						f->fetchMessage(msg, vmime::net::fetchAttributes::ENVELOPE);

						std::string message = msg->getHeader()->generate();
						std::cout << "I found an email to send" << std::endl;
						// // std::cout << message << std::endl << std::endl;

						std::string sender = message.substr((message.find("<") + 1), (message.find(">") - message.find("<") - 1));
						// std::cout << "sender: " << sender << std::endl;

						std::string subject = message.substr((message.find("Subject: ") + 9), (message.find("From: ") - message.find("Subject: ") - 9));
						// std::cout << "subject: " << subject << std::endl << std::endl;;

						std::vector <std::string> matches = googleImages(subject);
						// std::cout << "matches found: " << matches.size() << std::endl;
						
						std::string response;
						for(int i = 0; i < matches.size()/2; i++){
							response += "<img src=\"" + matches[2*i] + "\">\r\n";
						}
						sendMessage(sender, response, subject);
						
					 	vmime::utility::path draftFolder("Sent");
						f->copyMessages(draftFolder, vmime::net::messageSet::byNumber(msg->getNumber()));
						f->deleteMessages(vmime::net::messageSet::byNumber(msg->getNumber()));
					}	
				}
				// move messages

				break;
					
			}
			catch (vmime::exception& e)
			{
				std::cerr << std::endl;
				std::cerr << e << std::endl;
			}
			catch (std::exception& e)
			{
				std::cerr << std::endl;
				std::cerr << "std::exception: " << e.what() << std::endl;
			}
		} // for(cont)

		st->disconnect();
	}
	catch (vmime::exception& e)
	{
		std::cerr << std::endl;
		std::cerr << e << std::endl;
		throw;
	}
	catch (std::exception& e)
	{
		std::cerr << std::endl;
		std::cerr << "std::exception: " << e.what() << std::endl;
		throw;
	}
}

/* Show the main menu.
 *
 * @return true to quit the program, false to continue
 */


int main()
{
	// Set the global C and C++ locale to the user-configured locale.
	// The locale should use UTF-8 encoding for these tests to run successfully.
	try
	{
		std::locale::global(std::locale(""));
	}
	catch (std::exception &)
	{
		std::setlocale(LC_ALL, "");
	}

	for (bool quit = false ; !quit ; )
	{
		// Loop on main menu
		connectStore();
	}

	return 0;
}
