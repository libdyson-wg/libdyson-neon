import signal
import sys
import time

import paho.mqtt.client as mqtt


def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT broker. Press Ctrl+C to exit.")
    client.subscribe("#")


def on_message(client, userdata, msg):
    print("Received message on topic: {}".format(msg.topic))
    print("Message: {}".format(msg.payload.decode()))
    print("---------------------")


def on_signal(signum, frame):
    print("\nReceived SIGTERM signal. Disconnecting from MQTT broker...")
    client.disconnect()
    sys.exit(0)


# Set up MQTT client
client = mqtt.Client(client_id="mqtt-subscriber")
client.username_pw_set("X3V-US-RKA0414A", "8qno2lc/IRy2xAFUem4u6AwBmk8YzWiDesTCS37VcSuphygAry+LDukJWfS1y93iYqGvWIaJ4xOWxu5r4OS+3g==")

# Set up signal handler for SIGTERM
signal.signal(signal.SIGTERM, on_signal)

# Set up MQTT client callbacks
client.on_connect = on_connect
client.on_message = on_message

# Connect to MQTT broker
client.connect("192.168.1.137", 1883, 60)

# Start the MQTT loop
client.loop_start()

try:
    # Keep the script running until SIGTERM is received
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    # Handle Ctrl+C
    print("\nInterrupted by user. Disconnecting from MQTT broker...")
    client.disconnect()
    sys.exit(0)