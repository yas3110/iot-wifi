simple PufAuthApp
{
    parameters:
        double authInterval @unit(s) = default(5s);
        double authStartTime @unit(s) = default(1s);
    gates:
        input directIn @directIn;
}
