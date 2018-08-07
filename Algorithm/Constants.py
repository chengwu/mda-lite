# Flows that did not answer by ttl.
max_ttl = 30
black_flows = {}
# Check if too much negative deltas
default_timeout = 3
default_meshing_link_timeout = 3
default_icmp_rate_limit = 50


#give_up_probes
give_up_probes = 30000

#give_up rate
give_up_undesponsive_rate = 0.05


stochastic_timeout = 0.75

# Batching growth
batching_growth = 0.2

# mda batch size when using stochastic probing
mda_batch = 5


# Link batches
max_batch_link_probe_size = 150

default_stop_on_consecutive_stars = 3

max_acceptable_asymmetry = 400

# Checking meshing flows
default_check_meshing_flows = 2

total_probe_sent = 0

total_replies = 0