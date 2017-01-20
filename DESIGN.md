# 目目連 design notes

- Main entry point associates a packet with a flow and dispatches to the flow's function chain.
- A flow is associated with a running goroutine which takes packets for its flow from a channel and processes them.
- Flowtable behavior completely defined by function chains called for specific kinds of packets.