using MongoDB.Bson.Serialization.Attributes;

namespace NganHangDe_Backend.Models
{
    public class QuestionInfo : Question
    {
        // Remove the Id property since it's already inherited from Question
        public Subject Subject { get; set; } = null!;
        // Remove CreatedBy as it's already in the base Question class
    }
}
