package Iniro.kTrip.util;

import Iniro.kTrip.domain.Review;
import Iniro.kTrip.dto.ReviewDto;

public class ReviewConverter {
    public static ReviewDto convertToDto(Review review) {
        return ReviewDto.builder()
                .point(review.getPoint())
                .content(review.getContent())
                .writedate(review.getWritedate())
                .nickname(review.getMember().getNickname())
                .build();
    }
}