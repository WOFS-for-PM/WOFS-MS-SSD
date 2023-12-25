#!/usr/bin/env bash

# Set the number of poll queues to 32
echo 32 | sudo tee /sys/module/nvme/parameters/poll_queues
# Enable io poll
echo 1 | sudo tee /sys/block/nvme0n1/queue/io_poll
# Reset the controller
echo 1 | sudo tee /sys/block/nvme0n1/device/reset_controller