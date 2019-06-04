const Event = require("../../models/event");
const { transformEvent } = require("./merge");

module.exports = {
  // resolver for the 'events' query
  events: async () => {
    try {
      const events = await Event.find();
      return events.map(event => {
        return transformEvent(event);
      });
    } catch (err) {
      throw err;
    }
  },

  // resolver for the 'createEvent' mutation
  createEvent: async args => {
    const event = new Event({
      title: args.eventInput.title,
      description: args.eventInput.description,
      price: +args.eventInput.price,
      date: new Date(args.eventInput.date),
      creator: "5cf10fdf3c4d35277cac3fe4"
    });

    let createdEvent;

    try {
      const result = await event.save();
      createdEvent = transformEvent(result);
      const creator = await User.findById("5cf10fdf3c4d35277cac3fe4");

      if (!creator) {
        throw new Error("User not found.");
      }
      creator.createdEvents.push(event);
      await creator.save();

      return createdEvent;
    } catch (err) {
      console.log(err);
      throw err;
    }
  }
};
