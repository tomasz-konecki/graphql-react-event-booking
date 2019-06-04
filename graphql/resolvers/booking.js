const Event = require("../../models/event");
const Booking = require("../../models/booking");
const { transformBooking, transformEvent } = require("./merge");

module.exports = {
  // resolver for the 'bookings' query
  bookings: async () => {
    try {
      const bookings = await Booking.find();
      return bookings.map(booking => {
        return transformBooking(booking);
      });
    } catch (err) {
      throw err;
    }
  },

  // resolver for the 'bookEvent' mutation
  bookEvent: async args => {
    try {
      const fetchedEvent = await Event.findOne({ _id: args.eventId });
      const booking = new Booking({
        user: "5cf10fdf3c4d35277cac3fe4",
        event: fetchedEvent
      });
      const result = await booking.save();
      return transformBooking(result);
    } catch (err) {
      console.log(err);
    }
  },

  // resolver for the 'cancelBooking' mutation
  cancelBooking: async args => {
    try {
      const booking = await Booking.findById(args.bookingId).populate("event");
      const event = transformEvent(booking.event);
      await Booking.deleteOne({ _id: args.bookingId });
      return event;
    } catch (err) {
      throw err;
    }
  }
};
