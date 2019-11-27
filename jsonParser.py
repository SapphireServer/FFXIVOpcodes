import argparse
import sys
import wget
import os
import json

sys.path = ["../"] + sys.path
import CppHeaderParser

def sapphire2json( cppHeader ):
  opCodeJson = []
  for x in cppHeader.enums:
    channel = {}
    channel[ "opcodes" ] = []
    for value in x["values"]:
      channel[ "opcodes" ].append( { "name" : value[ "name" ], "code" : value[ "value" ] } )
    channel[ "channel" ] = x[ "name" ]
    opCodeJson.append( channel )
  print json.dumps( opCodeJson, sort_keys=True )

def json2sapphire():
  print( "do things" )

# implement handling of your mode here
def handleMode( mode, branch ):
  if mode == "sapphire2json":
    sapphire2json( getCppEnumStruct( branch ) )
  elif mode == "json2sapphire":
    json2sapphire()
  else:
    print( "unknown mode" )

def getCppEnumStruct( branch ):
  try:
    filePath = "Ipcs.h"
    if os.path.exists( filePath ):
      print( "Removing current Ipcs.h..." )
      os.remove( filePath )
    url = 'https://raw.githubusercontent.com/SapphireServer/Sapphire/' + branch + '/src/common/Network/PacketDef/Ipcs.h'
    print( "Downloading Ipcs.h from " + url )
    filename = wget.download(url)
    cppHeader = CppHeaderParser.CppHeader( "Ipcs.h" )
  except CppHeaderParser.CppParseError as e:
    print( e )
    sys.exit( 1 )
  return cppHeader

# entry point
def main():
  parser = argparse.ArgumentParser()
  parser.add_argument( '--mode', help='sapphire2json|json2sapphire' )
  parser.add_argument( '--branch', help='Which sapphire branch to pull from' )
  args = parser.parse_args()
  if args.mode == None:
    print( "Mode not set!")
    parser.print_help()
    sys.exit(1)
  if args.branch == None:
    print( "No source branch for Ipc.h given!" )
    sys.exit(1)

  handleMode( args.mode, args.branch )

main()

