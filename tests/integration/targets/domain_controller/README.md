# microsoft.ad.domain_controller tests

As this cannot be run in CI this is a brief guide on how to run these tests locally.
Run the following:

```bash
vagrant up

ansible-playbook setup.yml
```

It is a good idea to create a snapshot of both hosts before running the tests.
This allows you to reset the host back to a blank starting state if the tests need to be rerun.
To create a snaphost do the following:

```bash
virsh snapshot-create-as --domain "domain_controller_DC" --name "pretest"
virsh snapshot-create-as --domain "domain_controller_TEST" --name "pretest"
```

To restore these snapshots run the following:

```bash
virsh snapshot-revert --domain "domain_controller_DC" --snapshotname "pretest" --running
virsh snapshot-revert --domain "domain_controller_TEST" --snapshotname "pretest" --running
```

Once you are ready to run the tests run the following:

```bash
ansible-playbook test.yml
```

Run `vagrant destroy` to remove the test VMs.
