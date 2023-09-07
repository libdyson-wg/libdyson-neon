from ..libdyson import DysonPureHotCool

dev = DysonPureHotCool(
    serial='X3V-US-RKA0414A',
    credential='8qno2lc/IRy2xAFUem4u6AwBmk8YzWiDesTCS37VcSuphygAry+LDukJWfS1y93iYqGvWIaJ4xOWxu5r4OS+3g==',
    device_type="527K"
)

dev.connect('192.168.1.137')

print(dev.humidity)

print(dev.is_on)
