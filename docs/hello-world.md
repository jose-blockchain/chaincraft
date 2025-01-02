# Hello World Tutorial 

This tutorial demonstrates running a simple "Hello World" example using Chaincraft nodes.

## Prerequisites
- Python 3.6+
- chaincraft-cli.py

## Default Client Options
If no options are provided, the client defaults to:
- Debugging off
- Port 21000
- Persistent storage 

## Steps

1. Open 3 terminal windows.

2. In each terminal, navigate to the directory with chaincraft-cli.py. 

3. Start nodes on ports 21001, 21002, 21003:

   Terminal 1: `python chaincraft-cli.py -p 21001`
   Terminal 2: `python chaincraft-cli.py -p 21002`
   Terminal 3: `python chaincraft-cli.py -p 21003`

4. In Terminal 1, enter this JSON and press Enter: 

   ```json
   {"message": "Hello, world!"}
   ```

5. See the message gossiped to nodes in Terminal 2 and 3.

6. Send more messages from different nodes.

7. Ctrl+C in each terminal to shut down.

You've run a basic Chaincraft example showing message gossiping between nodes.