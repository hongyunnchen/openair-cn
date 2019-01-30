/*
* Copyright (c) 2017 Sprint
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "logger.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <memory>

Logger *Logger::m_singleton = NULL;

void Logger::_init( const char *app )
{
   spdlog::set_async_mode( 2048 );

   m_sinks.push_back( std::make_shared<spdlog::sinks::syslog_sink>() );
   m_sinks.push_back( std::make_shared<spdlog::sinks::ansicolor_stdout_sink_mt>() );
   std::string filename = fmt::format("./{}.log", app);
   m_sinks.push_back( std::make_shared<spdlog::sinks::rotating_file_sink_mt>( filename, 5 * 1024 * 1024, 3 ) );

   m_sinks[0].get()->set_level( spdlog::level::trace );
   m_sinks[1].get()->set_level( spdlog::level::trace );
   m_sinks[2].get()->set_level( spdlog::level::trace );

   std::cerr << "sink size = " << m_sinks.size() << std::endl;

   std::stringstream ss;
   ss << "[%Y-%m-%dT%H:%M:%S.%f] [" << app << "] [%n] [%l] %v";

   m_async_cmd = new _Logger( "async_c ", m_sinks, ss.str().c_str() );
   m_gtpv1_u   = new _Logger( "gtpv1_u ", m_sinks, ss.str().c_str() );
   m_gtpv2_c   = new _Logger( "gtpv2_c ", m_sinks, ss.str().c_str() );
   m_gx        = new _Logger( "gx      ", m_sinks, ss.str().c_str() );
   m_itti      = new _Logger( "itti    ", m_sinks, ss.str().c_str() );
   m_mme_s11   = new _Logger( "mme_s11 ", m_sinks, ss.str().c_str() );
   m_pgwc_app  = new _Logger( "pgwc_app", m_sinks, ss.str().c_str() );
   m_pgwu_app  = new _Logger( "pgwu_app", m_sinks, ss.str().c_str() );
   m_pgwc_s5s8 = new _Logger( "pgwc_s5 ", m_sinks, ss.str().c_str() );
   m_pgw_udp   = new _Logger( "pgw_udp ", m_sinks, ss.str().c_str() );
   m_pgwc_sx   = new _Logger( "pgwc_sx ", m_sinks, ss.str().c_str() );
   m_pgwu_sx   = new _Logger( "pgwu_sx ", m_sinks, ss.str().c_str() );
   m_sgwc_app  = new _Logger( "sgwc_app", m_sinks, ss.str().c_str() );
   m_sgwu_app  = new _Logger( "sgwu_app", m_sinks, ss.str().c_str() );
   m_sgwc_s11  = new _Logger( "sgwc_s11", m_sinks, ss.str().c_str() );
   m_sgwc_s5s8 = new _Logger( "sgwc_s5 ", m_sinks, ss.str().c_str() );
   m_sgwc_sx   = new _Logger( "sgwc_sx ", m_sinks, ss.str().c_str() );
   m_sgwu_sx   = new _Logger( "sgwu_sx ", m_sinks, ss.str().c_str() );
   m_sgw_udp   = new _Logger( "sgw_udp ", m_sinks, ss.str().c_str() );
   m_system    = new _Logger( "system  ", m_sinks, ss.str().c_str() );
   m_udp       = new _Logger( "udp     ", m_sinks, ss.str().c_str() );
   m_pfcp      = new _Logger( "pfcp    ", m_sinks, ss.str().c_str() );
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

_Logger::_Logger( const char *category, std::vector<spdlog::sink_ptr> &sinks, const char *pattern )
   : m_log( category, sinks.begin(), sinks.end() )
{
  m_log.set_pattern( pattern );
  m_log.set_level( spdlog::level::trace );
}

void _Logger::trace( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltTrace, format, args );
   va_end( args );
}

void _Logger::trace( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltTrace, format.c_str(), args );
   va_end( args );
}

void _Logger::debug( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltDebug, format, args );
   va_end( args );
}

void _Logger::debug( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltDebug, format.c_str(), args );
   va_end( args );
}

void _Logger::info( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltInfo, format, args );
   va_end( args );
}

void _Logger::info( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltInfo, format.c_str(), args );
   va_end( args );
}

void _Logger::startup( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltStartup, format, args );
   va_end( args );
}

void _Logger::startup( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltStartup, format.c_str(), args );
   va_end( args );
}

void _Logger::warn( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltWarn, format, args );
   va_end( args );
}

void _Logger::warn( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltWarn, format.c_str(), args );
   va_end( args );
}

void _Logger::error( const char *format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltError, format, args );
   va_end( args );
}

void _Logger::error( const std::string &format, ... )
{
   va_list args;
   va_start( args, format );
   log( _ltError, format.c_str(), args );
   va_end( args );
}

void _Logger::log( _LogType lt, const char *format, va_list &args )
{
   char buffer[ 2048 ];

   vsnprintf( buffer, sizeof(buffer), format, args );

   switch ( lt )
   {
      case _ltTrace: m_log.trace( buffer ); break;
      case _ltDebug: m_log.debug( buffer ); break;
      case _ltInfo: m_log.info( buffer ); break;
      case _ltStartup: m_log.warn( buffer ); break;
      case _ltWarn: m_log.error( buffer ); break;
      case _ltError: m_log.critical( buffer ); break;
   }
}
